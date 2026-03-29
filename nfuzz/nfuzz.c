/*
 * nfuzz — raw IPv4 / TCP-UDP stream / optional Bluetooth L2CAP mutation harness
 * plus optional HTTP fuzz server (nmap-xyberpix)
 *
 * Raw mode: sends crafted IPv4 datagrams via a raw socket (IP_HDRINCL).
 * Stream mode: mutates an application payload over TCP or UDP to --dst/--dport.
 * L2CAP mode (Linux + libbluetooth when built): mutates payloads over connected L2CAP.
 * HTTP mode: serves dynamically generated HTML/JS for authorized browser
 * (DOM/JS engine) fuzzing on a local or explicitly allowed bind address.
 *
 * Requires explicit --authorized (or NFUZZ_AUTHORIZED=1).
 *
 * Nmap and nfuzz are (C) Nmap Software LLC — see LICENSE in the distribution.
 */

/* libpcap uses BSD u_int/u_char; Darwin needs this before POSIX limits visibility. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_CONFIG_H
#include "nmap_config.h"
#endif
#ifdef HAVE_BLUETOOTH_L2CAP
#ifdef __APPLE__
#include "bt_l2cap_mac.h"
#else
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#endif
#endif

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

/* libpcap headers expect BSD u_int / u_char (see pcap(3pcap)). */
#include <pcap.h>

#ifndef IPPROTO_IP
#define IPPROTO_IP 0
#endif

#ifndef IP_HDRINCL
#if defined(__linux__)
#define IP_HDRINCL 3
#elif defined(__APPLE__)
#define IP_HDRINCL 2
#else
#define IP_HDRINCL 3
#endif
#endif

#define NFUZZ_MAX_PACKET 65535
#define NFUZZ_MAX_COUNT 10000000UL
#define NFUZZ_MAX_RATE 1000000u

#define NFUZZ_HTTP_MAX_BODY (512 * 1024)
#define NFUZZ_HTTP_DEFAULT_MAX_BODY (256 * 1024)
#define NFUZZ_HTTP_REQ_MAX 8192
#define NFUZZ_HTTP_DEFAULT_BIND "127.0.0.1:8787"
#define NFUZZ_HTTP_DEFAULT_REFRESH 2
#define NFUZZ_BROWSER_MAX_EXTRA 32
#define NFUZZ_BROWSER_CMD_MAX 512
#define NFUZZ_BROWSER_URL_MAX 768

/* Stream (TCP/UDP) and L2CAP fuzzing: application payload only */
#define NFUZZ_PROTO_DEFAULT_PAYLOAD 256
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* IPv4 "more fragments" flag (high byte of frag offset field, RFC 791). */
#ifndef NFUZZ_IP_MF
#define NFUZZ_IP_MF 0x2000
#endif

#ifndef TH_SYN
#define TH_SYN 0x02
#endif

struct nfuzz_http_browser_opts {
  int auto_browser;
  const char *browser_cmd;
  int browser_preset; /* 0=chromium 1=firefox 2=none */
  unsigned browser_restart_sec;
  const char *browser_url_override;
  char **browser_extra;
  int browser_extra_n;
};

static int parse_inaddr(const char *s, struct in_addr *out);
static uint32_t now_ns(void);

static int bappendf(char *buf, size_t cap, size_t *pos, const char *fmt, ...)
{
  if (*pos >= cap)
    return -1;
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf + *pos, cap - *pos, fmt, ap);
  va_end(ap);
  if (n < 0 || (size_t)n >= cap - *pos)
    return -1;
  *pos += (size_t)n;
  return 0;
}

static int bappend_bytes(char *buf, size_t cap, size_t *pos, const void *data,
    size_t len)
{
  if (cap - *pos < len)
    return -1;
  memcpy(buf + *pos, data, len);
  *pos += len;
  return 0;
}

static uint32_t prng32(uint32_t *s);

static int is_loopback_v4(struct in_addr *a)
{
  uint32_t h = ntohl(a->s_addr);
  return (h >> 24) == 127;
}

static void gen_random_ident(char *out, size_t outsz, uint32_t *rng)
{
  static const char alnum[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
  size_t n = 4 + (prng32(rng) % 12);
  if (n + 1 > outsz)
    n = outsz - 1;
  for (size_t i = 0; i < n; i++)
    out[i] = alnum[prng32(rng) % (sizeof(alnum) - 1)];
  out[n] = '\0';
}

/* Append fuzzed JS-like source (not guaranteed valid; stresses lexer/parser). */
static int append_js_blob(char *buf, size_t cap, size_t *pos, uint32_t *rng,
    size_t min_len, size_t max_len)
{
  static const char *kw[] = {
    "function", "var", "let", "const", "if", "else", "return", "while",
    "for", "try", "catch", "new", "typeof", "void", "await", "yield",
    "class", "extends", "super", "import", "export", "default", NULL
  };
  static const char *ids[] = {
    "document", "window", "navigator", "location", "history", "localStorage",
    "sessionStorage", "performance", "crypto", "console", "Math", "JSON",
    "Array", "Uint8Array", "Map", "Set", "Proxy", "Reflect", "Symbol", NULL
  };

  size_t target = min_len;
  if (max_len > min_len)
    target += prng32(rng) % (max_len - min_len + 1);

  while (*pos < cap - 64 && *pos < target) {
    int k = (int)(prng32(rng) % 12);
    if (k <= 2) {
      const char *w = kw[prng32(rng) % 22];
      if (bappendf(buf, cap, pos, "%s ", w) != 0)
        return -1;
    } else if (k <= 4) {
      char id[32];
      gen_random_ident(id, sizeof(id), rng);
      if (bappendf(buf, cap, pos, "%s", id) != 0)
        return -1;
    } else if (k == 5) {
      static const char punct[] = "(){}[];,.=<>+-*/%&|^~!?:";
      char ch = punct[prng32(rng) % (sizeof(punct) - 1)];
      if (bappendf(buf, cap, pos, " %c ", ch) != 0)
        return -1;
    } else if (k == 6) {
      int qlen = 1 + (int)(prng32(rng) % 48);
      if (bappendf(buf, cap, pos, "'") != 0)
        return -1;
      for (int i = 0; i < qlen && *pos < cap - 8; i++) {
        unsigned char c = (unsigned char)(prng32(rng) & 0xff);
        if (c == '\'' || c == '\\' || c == '\r' || c == '\n')
          c = (unsigned char)('a' + (prng32(rng) % 26));
        if (prng32(rng) % 5 == 0) {
          if (bappendf(buf, cap, pos, "\\x%02x", (unsigned)c) != 0)
            return -1;
        } else {
          if (bappend_bytes(buf, cap, pos, &c, 1) != 0)
            return -1;
        }
      }
      if (bappendf(buf, cap, pos, "'") != 0)
        return -1;
    } else if (k == 7) {
      if (bappendf(buf, cap, pos, "`") != 0)
        return -1;
      int tl = (int)(prng32(rng) % 32);
      for (int i = 0; i < tl && *pos < cap - 8; i++) {
        unsigned char c = (unsigned char)(prng32(rng) & 0xff);
        if (c == '`' || c == '\\')
          c = 'x';
        if (bappend_bytes(buf, cap, pos, &c, 1) != 0)
          return -1;
      }
      if (bappendf(buf, cap, pos, "`") != 0)
        return -1;
    } else if (k == 8) {
      const char *id = ids[prng32(rng) % 18];
      if (bappendf(buf, cap, pos, "%s", id) != 0)
        return -1;
    } else if (k == 9) {
      if (bappendf(buf, cap, pos, "/*") != 0)
        return -1;
      int cl = (int)(prng32(rng) % 80);
      for (int i = 0; i < cl && *pos < cap - 8; i++) {
        char c = (char)(' ' + (prng32(rng) % 95));
        if (c == '*' || c == '/')
          c = 'x';
        if (bappend_bytes(buf, cap, pos, &c, 1) != 0)
          return -1;
      }
      if (bappendf(buf, cap, pos, "*/") != 0)
        return -1;
    } else if (k == 10) {
      unsigned u = prng32(rng);
      if (bappendf(buf, cap, pos, "0x%x", u) != 0)
        return -1;
    } else {
      if (bappendf(buf, cap, pos, "\n") != 0)
        return -1;
    }
  }
  return 0;
}

static int build_http_fuzz_page(char *body, size_t cap, size_t *out_len,
    uint32_t *rng, unsigned refresh_sec)
{
  size_t pos = 0;
  char id1[40], id2[40], id3[40];
  gen_random_ident(id1, sizeof(id1), rng);
  gen_random_ident(id2, sizeof(id2), rng);
  gen_random_ident(id3, sizeof(id3), rng);

  if (bappendf(body, cap, &pos,
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n"
        "<title>nfuzz browser fuzz %08x</title>\n",
        (unsigned)prng32(rng))
      != 0)
    return -1;

  if (refresh_sec > 0) {
    if (bappendf(body, cap, &pos,
          "<meta http-equiv=\"refresh\" content=\"%u;url=/\">\n",
          refresh_sec)
        != 0)
      return -1;
  }

  if (bappendf(body, cap, &pos,
        "</head><body data-gen=\"%u\">\n"
        "<h1>nfuzz</h1><p>Authorized lab fuzz page; reload or wait for refresh.</p>\n",
        (unsigned)prng32(rng))
      != 0)
    return -1;

  /* Malformed / nested markup stress */
  int divs = 1 + (int)(prng32(rng) % 8);
  for (int d = 0; d < divs; d++) {
    char did[32];
    gen_random_ident(did, sizeof(did), rng);
    if (bappendf(body, cap, &pos,
          "<div id=\"%s\" class=\"%s\" data-u=\"&#%u;\">\n",
          did, id1, (unsigned)(prng32(rng) % 0x10ffff))
        != 0)
      return -1;
    if (prng32(rng) % 3 == 0) {
      if (bappendf(body, cap, &pos, "<!-- unclosed comment ") != 0)
        return -1;
    }
    if (prng32(rng) % 2 == 0) {
      if (bappendf(body, cap, &pos,
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\">"
            "<path d=\"M0,0 L%d,%d Q%d,%d %d,%d z\"/></svg>\n",
            (int)(prng32(rng) % 200), (int)(prng32(rng) % 200),
            (int)(prng32(rng) % 100), (int)(prng32(rng) % 100),
            (int)(prng32(rng) % 50), (int)(prng32(rng) % 50))
          != 0)
        return -1;
    }
  }

  if (bappendf(body, cap, &pos, "<script>\n\"use strict\";\n") != 0)
    return -1;
  if (append_js_blob(body, cap, &pos, rng, 400, 4000) != 0)
    return -1;

  if (bappendf(body, cap, &pos,
        "\n;try{var %s=document.createElement('div');"
        "%s.id='%s';document.body.appendChild(%s);"
        "%s.innerHTML='<span\\u0000bad>%s</span>';}catch(e){}\n",
        id1, id1, id2, id1, id1, id3)
      != 0)
    return -1;

  if (append_js_blob(body, cap, &pos, rng, 200, 2500) != 0)
    return -1;

  if (bappendf(body, cap, &pos,
        "\n;try{Object.defineProperty(document.body,'%s',{get:function(){"
        "return %u;}});}catch(e){}\n",
        id2, (unsigned)prng32(rng))
      != 0)
    return -1;

  if (bappendf(body, cap, &pos, "</script>\n") != 0)
    return -1;

  /* Second script: DOM API noise */
  if (bappendf(body, cap, &pos, "<script>\n") != 0)
    return -1;
  if (append_js_blob(body, cap, &pos, rng, 300, 3500) != 0)
    return -1;
  if (bappendf(body, cap, &pos, "\n</script>\n") != 0)
    return -1;

  for (int d = 0; d < divs; d++) {
    if (bappendf(body, cap, &pos, "</div>\n") != 0)
      return -1;
  }

  if (bappendf(body, cap, &pos, "</body></html>\n") != 0)
    return -1;

  *out_len = pos;
  return 0;
}

static int write_pid_file(const char *path)
{
#ifdef O_NOFOLLOW
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
#else
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
#endif
  if (fd < 0) {
    fprintf(stderr, "nfuzz: cannot write pid file %s: %s\n", path,
        strerror(errno));
    return -1;
  }
  char line[64];
  int ln = snprintf(line, sizeof(line), "%ld\n", (long)getpid());
  if (ln < 0 || (size_t)ln >= sizeof(line)) {
    close(fd);
    return -1;
  }
  if (write(fd, line, (size_t)ln) != (ssize_t)ln) {
    fprintf(stderr, "nfuzz: write pid file %s: %s\n", path, strerror(errno));
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

static int detach_server(void)
{
  pid_t p = fork();
  if (p < 0) {
    perror("nfuzz: fork");
    return -1;
  }
  if (p > 0)
    _exit(0);
  if (setsid() < 0) {
    perror("nfuzz: setsid");
    return -1;
  }
  p = fork();
  if (p < 0) {
    perror("nfuzz: fork");
    return -1;
  }
  if (p > 0)
    _exit(0);
  (void)chdir("/");
  int fd = open("/dev/null", O_RDWR);
  if (fd >= 0) {
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2)
      close(fd);
  }
  return 0;
}

static int parse_bind(const char *bind, char *host_out, size_t host_sz,
    uint16_t *port_out)
{
  const char *colon = strrchr(bind, ':');
  if (!colon || colon == bind)
    return -1;
  size_t hlen = (size_t)(colon - bind);
  if (hlen >= host_sz)
    return -1;
  memcpy(host_out, bind, hlen);
  host_out[hlen] = '\0';
  unsigned long p = strtoul(colon + 1, NULL, 10);
  if (p == 0 || p > 65535)
    return -1;
  *port_out = (uint16_t)p;
  return 0;
}

/* "\r\n\r\n" in a byte range (HTTP end-of-headers); not NUL-terminated. */
static size_t nfuzz_http_header_end(const char *buf, size_t len)
{
  if (len < 4)
    return (size_t)-1;
  for (size_t i = 0; i + 3 < len; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r'
        && buf[i + 3] == '\n')
      return i + 4;
  }
  return (size_t)-1;
}

/* Browser URL is passed to execvp; reject NUL/control bytes and DEL. */
static int nfuzz_browser_url_safe(const char *s)
{
  if (s == NULL || *s == '\0')
    return -1;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p < 0x20u || *p == 0x7fu)
      return -1;
  }
  return 0;
}

static volatile sig_atomic_t nfuzz_http_stop;

static void nfuzz_http_sig(int s)
{
  (void)s;
  nfuzz_http_stop = 1;
}

static int build_browser_url(char *out, size_t osz, const char *bind_ip,
    uint16_t port, const char *override)
{
  const char *host = bind_ip;
  if (override != NULL && override[0] != '\0') {
    if (nfuzz_browser_url_safe(override) != 0)
      return -1;
    size_t olen = strlen(override);
    if (olen >= osz)
      return -1;
    memcpy(out, override, olen);
    out[olen] = '\0';
    return 0;
  }
  if (strcmp(bind_ip, "0.0.0.0") == 0)
    host = "127.0.0.1";
  int n = snprintf(out, osz, "http://%s:%u/", host, (unsigned)port);
  if (n < 0 || (size_t)n >= osz)
    return -1;
  if (nfuzz_browser_url_safe(out) != 0)
    return -1;
  return 0;
}

static pid_t nfuzz_browser_spawn(const char *cmd, const char *url, int preset,
    char **extra, int extra_n)
{
  pid_t p = fork();
  if (p < 0) {
    perror("nfuzz: fork (browser)");
    return (pid_t)-1;
  }
  if (p > 0)
    return p;

  char *argv[64];
  int ac = 0;
  argv[ac++] = (char *)cmd;
  if (preset == 0) {
    argv[ac++] = "--headless=new";
    argv[ac++] = "--disable-gpu";
    argv[ac++] = "--no-sandbox";
    argv[ac++] = "--disable-dev-shm-usage";
    argv[ac++] = "--disable-software-rasterizer";
  } else if (preset == 1) {
    argv[ac++] = "--headless";
  }
  for (int i = 0; i < extra_n && ac < 60; i++)
    argv[ac++] = extra[i];
  argv[ac++] = (char *)url;
  argv[ac] = NULL;
  execvp(cmd, argv);
  _exit(126);
}

/* First non-empty line: METHOD SP request-target ... */
static void nfuzz_parse_http_request_line(const char *req, ssize_t reqlen,
    char *method, size_t method_cap, char *target, size_t target_cap)
{
  if (method_cap > 0)
    method[0] = '\0';
  if (target_cap > 0)
    target[0] = '\0';
  if (reqlen <= 0 || req == NULL)
    return;

  const char *p = req;
  const char *end = req + reqlen;
  while (p < end && (*p == '\r' || *p == '\n' || *p == ' ' || *p == '\t'))
    p++;
  const char *line = p;
  while (p < end && *p != '\r' && *p != '\n')
    p++;
  const char *line_end = p;
  if (line >= line_end)
    return;

  const char *m = line;
  while (m < line_end && *m != ' ')
    m++;
  size_t ml = (size_t)(m - line);
  if (ml >= method_cap)
    ml = method_cap > 0 ? method_cap - 1 : 0;
  if (method_cap > 0 && ml > 0) {
    memcpy(method, line, ml);
    method[ml] = '\0';
  }
  if (m >= line_end || *m != ' ')
    return;
  m++;
  while (m < line_end && *m == ' ')
    m++;
  const char *u = m;
  while (u < line_end && *u != ' ')
    u++;
  size_t ul = (size_t)(u - m);
  if (ul >= target_cap)
    ul = target_cap > 0 ? target_cap - 1 : 0;
  if (target_cap > 0 && ul > 0) {
    memcpy(target, m, ul);
    target[ul] = '\0';
  }
}

static void nfuzz_sanitize_log_token(char *s)
{
  if (s == NULL)
    return;
  for (size_t i = 0; s[i] != '\0'; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x20 || c > 0x7e)
      s[i] = '?';
  }
}

/* argv tokens for execvp: no shell, but reject control bytes and shell metacharacters. */
static int nfuzz_browser_argv_token_safe(const char *s)
{
  if (s == NULL || *s == '\0')
    return -1;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p < 0x20u || *p == 0x7fu)
      return -1;
    switch ((char)*p) {
    case ';':
    case '|':
    case '&':
    case '`':
    case '$':
      return -1;
    default:
      break;
    }
  }
  return 0;
}

/* http_status 0 means we dropped the connection without a valid response. */
static void nfuzz_http_log_request(int do_detach, const struct sockaddr_in *peer,
    const char *req, ssize_t reqlen, int http_status, size_t resp_body)
{
  if (do_detach)
    return;

  char abuf[INET_ADDRSTRLEN];
  const char *ip = inet_ntop(AF_INET, &peer->sin_addr, abuf, sizeof(abuf));
  if (ip == NULL)
    ip = "?";
  unsigned short pr = ntohs(peer->sin_port);

  if (reqlen <= 0) {
    fprintf(stderr, "nfuzz: http %s:%u no request data\n", ip, pr);
    return;
  }

  char method[24];
  char target[160];
  nfuzz_parse_http_request_line(req, reqlen, method, sizeof(method),
      target, sizeof(target));
  nfuzz_sanitize_log_token(method);
  nfuzz_sanitize_log_token(target);
  const char *ms = method[0] != '\0' ? method : "?";
  const char *ts = target[0] != '\0' ? target : "?";

  if (http_status == 0)
    fprintf(stderr, "nfuzz: http %s:%u %s %s -> dropped\n", ip, pr, ms, ts);
  else
    fprintf(stderr, "nfuzz: http %s:%u %s %s -> %d (%zu byte body)\n",
        ip, pr, ms, ts, http_status, resp_body);
}

static int run_http_daemon(const char *bind_spec, size_t max_body,
    unsigned refresh_sec, int do_detach, const char *pid_file,
    int allow_remote, long seed_arg,
    struct nfuzz_http_browser_opts *brw)
{
  char host[256];
  uint16_t port;
  if (parse_bind(bind_spec, host, sizeof(host), &port) != 0) {
    fprintf(stderr, "nfuzz: bad --http-bind (use HOST:PORT, e.g. %s)\n",
        NFUZZ_HTTP_DEFAULT_BIND);
    return 2;
  }

  struct in_addr bind_addr;
  if (parse_inaddr(host, &bind_addr) != 0) {
    fprintf(stderr, "nfuzz: http bind host must be IPv4\n");
    return 2;
  }
  if (!is_loopback_v4(&bind_addr) && !allow_remote) {
    fprintf(stderr,
        "nfuzz: non-loopback bind requires --http-allow-remote "
        "(authorized lab only)\n");
    return 2;
  }

  if (max_body < 4096 || max_body > NFUZZ_HTTP_MAX_BODY) {
    fprintf(stderr, "nfuzz: --http-max-body out of range\n");
    return 2;
  }

  signal(SIGPIPE, SIG_IGN);
  nfuzz_http_stop = 0;
  signal(SIGINT, nfuzz_http_sig);
  signal(SIGTERM, nfuzz_http_sig);

  if (do_detach) {
    if (detach_server() != 0)
      return 1;
  }

  int ls = socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0) {
    perror("nfuzz: socket");
    return 1;
  }
  int one = 1;
  setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr = bind_addr;

  if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
    fprintf(stderr, "nfuzz: bind %s: %s\n", bind_spec, strerror(errno));
    close(ls);
    return 1;
  }
  if (listen(ls, 16) != 0) {
    perror("nfuzz: listen");
    close(ls);
    return 1;
  }

  if (pid_file && write_pid_file(pid_file) != 0) {
    close(ls);
    return 1;
  }

  if (!do_detach)
    fprintf(stderr, "nfuzz: HTTP fuzz daemon listening on http://%s/ "
        "(Ctrl-C to stop)\n", bind_spec);

  uint32_t rng = (uint32_t)(seed_arg >= 0 ? seed_arg : (long)time(NULL) ^ (long)now_ns());
  if (rng == 0)
    rng = 0xbeefcafeu;

  char *body = (char *)malloc(max_body + 256);
  if (!body) {
    close(ls);
    return 1;
  }

  char browser_url[NFUZZ_BROWSER_URL_MAX];
  pid_t browser_pid = 0;
  time_t browser_epoch = 0;
  const char *browser_cmd_resolved = NULL;
  char browser_cmd_buf[NFUZZ_BROWSER_CMD_MAX];

  if (brw != NULL && brw->auto_browser) {
    if (build_browser_url(browser_url, sizeof(browser_url), host, port,
          brw->browser_url_override) != 0) {
      fprintf(stderr,
          "nfuzz: browser URL invalid (too long, control characters, or bad "
          "--browser-url)\n");
      free(body);
      close(ls);
      return 2;
    }
    browser_cmd_resolved = brw->browser_cmd;
    if (browser_cmd_resolved == NULL || browser_cmd_resolved[0] == '\0')
      browser_cmd_resolved = getenv("NFUZZ_BROWSER_CMD");
    if (browser_cmd_resolved == NULL || browser_cmd_resolved[0] == '\0')
      browser_cmd_resolved = "chromium";
    size_t cmdlen = strlen(browser_cmd_resolved);
    if (cmdlen >= sizeof(browser_cmd_buf)) {
      fprintf(stderr, "nfuzz: --browser-cmd too long\n");
      free(body);
      close(ls);
      return 2;
    }
    memcpy(browser_cmd_buf, browser_cmd_resolved, cmdlen);
    browser_cmd_buf[cmdlen] = '\0';
    browser_cmd_resolved = browser_cmd_buf;
    if (nfuzz_browser_argv_token_safe(browser_cmd_resolved) != 0) {
      fprintf(stderr,
          "nfuzz: --browser-cmd / NFUZZ_BROWSER_CMD must be one executable token "
          "without shell metacharacters (|;`$&) or ASCII control bytes (incl. DEL)\n");
      free(body);
      close(ls);
      return 2;
    }
    for (int bi = 0; bi < brw->browser_extra_n; bi++) {
      if (nfuzz_browser_argv_token_safe(brw->browser_extra[bi]) != 0) {
        fprintf(stderr,
            "nfuzz: each --browser-arg must be a single token without "
            ";|`$& or ASCII control bytes (incl. DEL)\n");
        free(body);
        close(ls);
        return 2;
      }
    }
    fprintf(stderr, "nfuzz: auto-browser enabled (%s -> %s)\n",
        browser_cmd_resolved, browser_url);
  }

  while (!nfuzz_http_stop) {
    if (brw != NULL && brw->auto_browser) {
      time_t now = time(NULL);
      if (browser_pid == 0) {
        browser_pid = nfuzz_browser_spawn(browser_cmd_resolved, browser_url,
            brw->browser_preset, brw->browser_extra, brw->browser_extra_n);
        if (browser_pid <= 0)
          browser_pid = 0;
        else
          browser_epoch = now;
      } else {
        int st = 0;
        pid_t w = waitpid(browser_pid, &st, WNOHANG);
        if (w == browser_pid) {
          if (!do_detach)
            fprintf(stderr, "nfuzz: browser exited (status %d), respawning\n",
                WIFEXITED(st) ? WEXITSTATUS(st) : -1);
          browser_pid = 0;
          continue;
        }
        if (brw->browser_restart_sec > 0 && browser_epoch > 0
            && (unsigned long)(now - browser_epoch)
                >= (unsigned long)brw->browser_restart_sec) {
          kill(browser_pid, SIGTERM);
          (void)waitpid(browser_pid, &st, 0);
          browser_pid = 0;
        }
      }
    }

    struct pollfd pfd;
    pfd.fd = ls;
    pfd.events = POLLIN;
    int timeout_ms = (brw != NULL && brw->auto_browser) ? 500 : -1;
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr < 0) {
      if (errno == EINTR)
        continue;
      perror("nfuzz: poll");
      break;
    }
    if (pr == 0)
      continue;
    if (!(pfd.revents & POLLIN))
      continue;

    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int c = accept(ls, (struct sockaddr *)&peer, &plen);
    if (c < 0) {
      if (errno == EINTR)
        continue;
      perror("nfuzz: accept");
      break;
    }

    char req[NFUZZ_HTTP_REQ_MAX];
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(req) - 1) {
      ssize_t n = recv(c, req + total, sizeof(req) - 1 - (size_t)total, 0);
      if (n <= 0)
        break;
      total += n;
      if (nfuzz_http_header_end(req, (size_t)total) != (size_t)-1)
        break;
    }

    if (total <= 0) {
      nfuzz_http_log_request(do_detach, &peer, req, total, 0, 0);
      close(c);
      continue;
    }

    size_t blen = 0;
    if (build_http_fuzz_page(body, max_body, &blen, &rng, refresh_sec) != 0
        || blen == 0) {
      const char *err =
          "HTTP/1.1 500 Internal Server Error\r\n"
          "Connection: close\r\n"
          "Content-Length: 0\r\n\r\n";
      (void)send(c, err, strlen(err), 0);
      nfuzz_http_log_request(do_detach, &peer, req, total, 500, 0);
      close(c);
      continue;
    }

    char hdr[512];
    size_t hpos = 0;
    if (bappendf(hdr, sizeof(hdr), &hpos,
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: text/html; charset=utf-8\r\n"
          "X-Content-Type-Options: nosniff\r\n"
          "Cache-Control: no-store\r\n"
          "Connection: close\r\n"
          "Content-Length: %zu\r\n\r\n",
          blen)
        != 0) {
      nfuzz_http_log_request(do_detach, &peer, req, total, 0, 0);
      close(c);
      continue;
    }

    (void)send(c, hdr, hpos, 0);
    (void)send(c, body, blen, 0);
    nfuzz_http_log_request(do_detach, &peer, req, total, 200, blen);
    close(c);
  }

  if (browser_pid > 0) {
    kill(browser_pid, SIGTERM);
    (void)waitpid(browser_pid, NULL, 0);
  }

  free(body);
  close(ls);
  if (!do_detach)
    fprintf(stderr, "nfuzz: HTTP daemon stopped\n");
  return 0;
}

static void usage(FILE *fp, const char *argv0)
{
  fprintf(fp,
"Usage: %s --authorized { --http-daemon [http-options] | stream-options |\n"
"                            bt-l2cap-options | raw-packet-options }\n"
"\n"
"Required:\n"
"  --authorized              Acknowledge written authorization for the target.\n"
"\n"
"HTTP browser fuzz daemon (serves fresh malformed HTML/JS per request):\n"
"  --http-daemon             Run HTTP server instead of raw IPv4 send mode.\n"
"  --http-bind HOST:PORT     Listen address (default %s).\n"
"  --http-max-body N        Max HTML body bytes (default %u).\n"
"  --http-refresh SEC       Meta refresh to / every SEC sec (0=off, default %d).\n"
"  --http-allow-remote      Allow bind outside 127.0.0.0/8 (required for LAN).\n"
"  --detach                 Double-fork to background (close stdio).\n"
"  --pid-file PATH          Write PID after detach (optional).\n"
"  --auto-browser           With --http-daemon: spawn headless browser to load fuzz URL.\n"
"  --browser-cmd CMD        Browser executable (default: NFUZZ_BROWSER_CMD or chromium).\n"
"  --browser-preset P       chromium | firefox | none (default: chromium).\n"
"  --browser-restart-sec N  SIGTERM and restart browser every N seconds (0=off).\n"
"  --browser-url URL        Full URL to open (default: http://HOST:PORT/ from bind).\n"
"  --browser-arg ARG        Extra argv before URL (repeatable; max %d).\n"
"\n"
"Stream mode (TCP or UDP application payload; mutually exclusive with raw and L2CAP):\n"
"  --proto PROTO            tcp | udp — connect/sendto to --dst and --dport.\n"
"  --proto-payload-len N    Base payload size when --hex/--hex-file omitted (default %d).\n"
"  --proto-reconnect        TCP: new connection per iteration (default: one connection).\n"
"  --proto-connect-timeout SEC  TCP connect wait (default 10, max 300).\n"
"\n"
"Bluetooth L2CAP mode (macOS IOBluetooth or Linux BlueZ when built; exclusive with raw and --proto):\n"
"  --bt-l2cap ADDR          Peer BD_ADDR (XX:XX:XX:XX:XX:XX).\n"
"  --bt-psm N               L2CAP PSM in host byte order (default 4097).\n"
"\n"
"Raw IPv4 mode:\n"
"Target / addressing:\n"
"  --dst ADDR                Destination IPv4 (also used for sendto).\n"
"  --src ADDR                Patch IPv4 header source field (optional).\n"
"  --patch-addresses         Apply --src/--dst to bytes 12-19 of the IP header.\n"
"\n"
"Payload (one of; stream/L2CAP use application bytes only):\n"
"  --hex-file PATH           Base datagram as hex (whitespace ignored).\n"
"  --hex STRING              Base datagram as hex string.\n"
"  --pcap PATH               Base datagram from IPv4 inside capture (libpcap; like Scapy rdpcap).\n"
"  --pcap-index N            Use Nth IPv4 packet in file (1-based, default 1).\n"
"  --template NAME           Built-in IPv4 stack (no hex): icmp-echo | udp | tcp-syn\n"
"                            (Scapy-style defaults; use --payload-len, ports, etc.).\n"
"  --sport N / --dport N     Source/dest port for udp/tcp-syn templates (0=default).\n"
"  --payload-len N           L4 payload bytes after fixed header (0=defaults: icmp 32, udp 16, tcp 0).\n"
"  --icmp-id N  --icmp-seq N ICMP echo identifier / sequence (icmp-echo template).\n"
"  --tcp-win N               TCP window for tcp-syn (0=8192).\n"
"  --ip-options-hex HEX      Raw IPv4 options after 20-byte header (multiple of 4 after NOP pad);\n"
"                            requires --template. Max 40 option bytes.\n"
"  --tcp-options-hex HEX     Raw TCP options after 20-byte header (tcp-syn only); padded with NOP to\n"
"                            multiple of 4. Combine with --tcp-mss (MSS option emitted first).\n"
"  --tcp-mss N               Append RFC 793 MSS option (tcp-syn template only).\n"
"\n"
"Fuzzing:\n"
"  -c, --count N             Packets to send (default 1, max %lu).\n"
"  -r, --rate RATE           Max packets/sec (0 = no limit, max %u).\n"
"  -s, --seed N              RNG seed (default: time).\n"
"  -S, --strategy NAME       bitflip | random_byte | inc_byte | dec_byte |\n"
"                            truncate | append_random | shuffle_block (default: bitflip).\n"
"  -m, --mutable-off O       Mutable region start (default: after IP header for hex;\n"
"                            after L4 header for --template).\n"
"  -l, --mutable-len L       Length of mutable region (default: through end of buffer).\n"
"\n"
"Checksums / lengths:\n"
"  --fix-ip-len              Set IPv4 total length field from buffer length (default on).\n"
"  --no-fix-ip-len\n"
"  --fix-checksums           Recompute IPv4 header checksum (default on).\n"
"  --no-fix-checksums\n"
"  --fix-l4                  Recompute UDP, TCP, or ICMPv4 checksum if present.\n"
"  --frag-mtu BYTES          If datagram exceeds BYTES, IPv4-fragment to fit (0=off).\n"
"                            -r/--rate sleeps once per logical packet (after all frags).\n"
"\n"
"Misc:\n"
"  -h, --help                This help.\n"
"  -V, --version             Version string.\n"
"\n"
"Environment:\n"
"  NFUZZ_AUTHORIZED=1        Same acknowledgement as --authorized (either is enough).\n"
"  NFUZZ_BROWSER_CMD         Default browser for --auto-browser if --browser-cmd omitted.\n"
"\n",
          argv0, NFUZZ_HTTP_DEFAULT_BIND,
          (unsigned)NFUZZ_HTTP_DEFAULT_MAX_BODY,
          NFUZZ_HTTP_DEFAULT_REFRESH, NFUZZ_BROWSER_MAX_EXTRA,
          NFUZZ_PROTO_DEFAULT_PAYLOAD,
          (unsigned long)NFUZZ_MAX_COUNT,
          NFUZZ_MAX_RATE);
}

static const char *version_string(void)
{
  return "nfuzz (nmap-xyberpix) 0.7.1";
}

static int xtoi(int c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* Decode hex from buffer; returns new length or -1 on error. */
static int decode_hex_buffer(const char *text, size_t tlen, unsigned char *out, int outmax)
{
  int o = 0;
  int hi = -1;
  for (size_t i = 0; i < tlen; i++) {
    unsigned char c = (unsigned char)text[i];
    if (isspace(c))
      continue;
    int v = xtoi((int)c);
    if (v < 0)
      return -1;
    if (hi < 0) {
      hi = v;
    } else {
      if (o >= outmax)
        return -1;
      out[o++] = (unsigned char)((hi << 4) | v);
      hi = -1;
    }
  }
  if (hi >= 0)
    return -1;
  return o;
}

static int read_hex_file(const char *path, unsigned char *out, int outmax)
{
#ifdef O_NOFOLLOW
  int fd = open(path, O_RDONLY | O_NOFOLLOW);
#else
  int fd = open(path, O_RDONLY);
#endif
  if (fd < 0) {
    fprintf(stderr, "nfuzz: cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    fprintf(stderr, "nfuzz: %s must be a regular file\n", path);
    close(fd);
    return -1;
  }
  off_t szo = st.st_size;
  if (szo < 0 || szo > (off_t)(NFUZZ_MAX_PACKET * 4)) {
    fprintf(stderr, "nfuzz: file too large or unreadable: %s\n", path);
    close(fd);
    return -1;
  }
  size_t sz = (size_t)szo;
  char *buf = (char *)malloc(sz + 1);
  if (!buf) {
    close(fd);
    return -1;
  }
  size_t r = 0;
  while (r < sz) {
    ssize_t n = read(fd, buf + r, sz - r);
    if (n <= 0) {
      fprintf(stderr, "nfuzz: read error on %s\n", path);
      free(buf);
      close(fd);
      return -1;
    }
    r += (size_t)n;
  }
  close(fd);
  buf[r] = '\0';
  int len = decode_hex_buffer(buf, r, out, outmax);
  free(buf);
  if (len < 0) {
    fprintf(stderr, "nfuzz: invalid hex in %s\n", path);
    return -1;
  }
  return len;
}

static uint16_t in_cksum(const unsigned char *p, size_t len)
{
  uint32_t sum = 0;
  size_t i;
  for (i = 0; i + 1 < len; i += 2)
    sum += (uint32_t)p[i] << 8 | p[i + 1];
  if (i < len)
    sum += (uint32_t)p[i] << 8;
  while (sum >> 16)
    sum = (sum & 0xffffu) + (sum >> 16);
  return (uint16_t)~sum;
}

static unsigned ip_header_len(const unsigned char *pkt, int len)
{
  if (len < 20)
    return 0;
  unsigned ihl = (pkt[0] & 0x0fu) * 4;
  if (ihl < 20 || (int)ihl > len)
    return 0;
  return ihl;
}

static void fix_ip_total_len(unsigned char *pkt, int len)
{
  if (len >= 4)
    pkt[2] = (unsigned char)((len >> 8) & 0xff), pkt[3] = (unsigned char)(len & 0xff);
}

static void fix_ipv4_hdr_checksum(unsigned char *pkt, int len)
{
  unsigned ihl = ip_header_len(pkt, len);
  if (ihl < 20)
    return;
  pkt[10] = pkt[11] = 0;
  uint16_t c = in_cksum(pkt, ihl);
  pkt[10] = (unsigned char)((c >> 8) & 0xff);
  pkt[11] = (unsigned char)(c & 0xff);
}

static void pseudo_sum_chunk(uint32_t *sum, const unsigned char *p, size_t len)
{
  size_t i;
  for (i = 0; i + 1 < len; i += 2)
    *sum += (uint32_t)p[i] << 8 | p[i + 1];
  if (i < len)
    *sum += (uint32_t)p[i] << 8;
}

static uint16_t finish_sum(uint32_t sum)
{
  while (sum >> 16)
    sum = (sum & 0xffffu) + (sum >> 16);
  return (uint16_t)~sum;
}

static void fix_udp_tcp_checksum(unsigned char *pkt, int len)
{
  unsigned ihl = ip_header_len(pkt, len);
  if (ihl < 20 || (int)ihl >= len)
    return;
  uint8_t proto = pkt[9];
  int l4len = len - (int)ihl;
  if (l4len < 4)
    return;

  if (proto == IPPROTO_ICMP) {
    pkt[ihl + 2] = pkt[ihl + 3] = 0;
    uint16_t c = in_cksum(pkt + ihl, (size_t)l4len);
    pkt[ihl + 2] = (unsigned char)((c >> 8) & 0xff);
    pkt[ihl + 3] = (unsigned char)(c & 0xff);
    return;
  }

  if (l4len < 8)
    return;

  unsigned char ph[12];
  memcpy(ph, pkt + 12, 4);
  memcpy(ph + 4, pkt + 16, 4);
  ph[8] = 0;
  ph[9] = proto;
  ph[10] = (unsigned char)((l4len >> 8) & 0xff);
  ph[11] = (unsigned char)(l4len & 0xff);

  if (proto == IPPROTO_UDP) {
    pkt[ihl + 4] = (unsigned char)((l4len >> 8) & 0xff);
    pkt[ihl + 5] = (unsigned char)(l4len & 0xff);
    pkt[ihl + 6] = pkt[ihl + 7] = 0;
    uint32_t sum = 0;
    pseudo_sum_chunk(&sum, ph, sizeof(ph));
    pseudo_sum_chunk(&sum, pkt + ihl, (size_t)l4len);
    uint16_t c = finish_sum(sum);
    if (c == 0)
      c = 0xffff;
    pkt[ihl + 6] = (unsigned char)((c >> 8) & 0xff);
    pkt[ihl + 7] = (unsigned char)(c & 0xff);
  } else if (proto == IPPROTO_TCP) {
    if (l4len < 20)
      return;
    pkt[ihl + 16] = pkt[ihl + 17] = 0;
    uint32_t sum = 0;
    pseudo_sum_chunk(&sum, ph, sizeof(ph));
    pseudo_sum_chunk(&sum, pkt + ihl, (size_t)l4len);
    uint16_t c = finish_sum(sum);
    pkt[ihl + 16] = (unsigned char)((c >> 8) & 0xff);
    pkt[ihl + 17] = (unsigned char)(c & 0xff);
  }
}

static int open_raw_socket(void)
{
  int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (fd < 0)
    return -1;
  int one = 1;
  if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

/* First byte past L4 header suitable for mutation (fixed hdr sizes for templates). */
static int nfuzz_payload_offset(const unsigned char *pkt, int len)
{
  unsigned ihl = ip_header_len(pkt, len);
  if (ihl < 20 || (int)ihl + 1 > len)
    return -1;
  uint8_t p = pkt[9];
  if (p == IPPROTO_ICMP)
    return (int)ihl + 8;
  if (p == IPPROTO_UDP)
    return (int)ihl + 8;
  if (p == IPPROTO_TCP) {
    if (len < (int)ihl + 20)
      return -1;
    unsigned thl = (unsigned)(pkt[ihl + 12] >> 4) * 4u;
    if (thl < 20u)
      thl = 20u;
    if ((int)(ihl + thl) > len)
      return -1;
    return (int)ihl + (int)thl;
  }
  return -1;
}

/* Scapy-style stacked IPv4 + ICMP echo / UDP / TCP-SYN; optional IP/TCP options. */
static int build_ipv4_template(unsigned char *out, int outmax, const char *tpl,
    struct in_addr dst, const struct in_addr *src, int have_src, uint16_t sport,
    uint16_t dport, unsigned payload_len, uint16_t icmp_id, uint16_t icmp_seq,
    uint16_t tcp_win, const unsigned char *ip_opts, unsigned ip_opt_len,
    const unsigned char *tcp_opts, unsigned tcp_opt_len, uint32_t *rng)
{
  if (ip_opt_len % 4 != 0 || ip_opt_len > 40)
    return -1;
  unsigned ip_hlen = 20 + ip_opt_len;
  if (ip_hlen > 60)
    return -1;
  unsigned ihl_words = ip_hlen / 4;
  if (ihl_words < 5 || ihl_words > 15)
    return -1;

  unsigned char sip[4];
  unsigned char dip[4];
  memcpy(dip, &dst.s_addr, 4);
  if (have_src && src != NULL)
    memcpy(sip, &src->s_addr, 4);
  else
    memset(sip, 0, 4);

  if (strcasecmp(tpl, "icmp-echo") == 0) {
    if (tcp_opt_len != 0)
      return -1;
    if (payload_len == 0)
      payload_len = 32;
    unsigned icmp_total = 8 + payload_len;
    unsigned tot = ip_hlen + icmp_total;
    if ((int)tot > outmax || tot < ip_hlen + 8)
      return -1;
    memset(out, 0, tot);
    out[0] = (unsigned char)(0x40 | (ihl_words & 0x0fu));
    out[1] = 0;
    out[2] = (unsigned char)(tot >> 8);
    out[3] = (unsigned char)tot;
    uint16_t ipid = (uint16_t)(prng32(rng) >> 16);
    out[4] = (unsigned char)(ipid >> 8);
    out[5] = (unsigned char)ipid;
    out[8] = 64;
    out[9] = IPPROTO_ICMP;
    memcpy(out + 12, sip, 4);
    memcpy(out + 16, dip, 4);
    if (ip_opt_len != 0)
      memcpy(out + 20, ip_opts, ip_opt_len);
    unsigned io = ip_hlen;
    out[io] = 8; /* echo request */
    out[io + 1] = 0;
    out[io + 4] = (unsigned char)(icmp_id >> 8);
    out[io + 5] = (unsigned char)icmp_id;
    out[io + 6] = (unsigned char)(icmp_seq >> 8);
    out[io + 7] = (unsigned char)icmp_seq;
    for (unsigned i = 0; i < payload_len; i++)
      out[io + 8 + i] = (unsigned char)(prng32(rng) & 0xff);
    return (int)tot;
  }

  if (strcasecmp(tpl, "udp") == 0) {
    if (tcp_opt_len != 0)
      return -1;
    if (payload_len == 0)
      payload_len = 16;
    if (sport == 0)
      sport = 45012;
    if (dport == 0)
      dport = 33434;
    unsigned udp_len = 8 + payload_len;
    unsigned tot = ip_hlen + udp_len;
    if ((int)tot > outmax)
      return -1;
    memset(out, 0, tot);
    out[0] = (unsigned char)(0x40 | (ihl_words & 0x0fu));
    out[1] = 0;
    out[2] = (unsigned char)(tot >> 8);
    out[3] = (unsigned char)tot;
    uint16_t ipid = (uint16_t)(prng32(rng) >> 16);
    out[4] = (unsigned char)(ipid >> 8);
    out[5] = (unsigned char)ipid;
    out[8] = 64;
    out[9] = IPPROTO_UDP;
    memcpy(out + 12, sip, 4);
    memcpy(out + 16, dip, 4);
    if (ip_opt_len != 0)
      memcpy(out + 20, ip_opts, ip_opt_len);
    unsigned io = ip_hlen;
    out[io + 0] = (unsigned char)(sport >> 8);
    out[io + 1] = (unsigned char)sport;
    out[io + 2] = (unsigned char)(dport >> 8);
    out[io + 3] = (unsigned char)dport;
    out[io + 4] = (unsigned char)(udp_len >> 8);
    out[io + 5] = (unsigned char)udp_len;
    for (unsigned i = 0; i < payload_len; i++)
      out[io + 8 + i] = (unsigned char)(prng32(rng) & 0xff);
    return (int)tot;
  }

  if (strcasecmp(tpl, "tcp-syn") == 0) {
    if (tcp_opt_len % 4 != 0 || tcp_opt_len > 40)
      return -1;
    unsigned tcp_total = 20 + tcp_opt_len;
    if (tcp_total > 60)
      return -1;
    if (sport == 0)
      sport = 45012;
    if (dport == 0)
      dport = 443;
    if (tcp_win == 0)
      tcp_win = 8192;
    unsigned tot = ip_hlen + tcp_total + payload_len;
    if ((int)tot > outmax)
      return -1;
    memset(out, 0, tot);
    out[0] = (unsigned char)(0x40 | (ihl_words & 0x0fu));
    out[1] = 0;
    out[2] = (unsigned char)(tot >> 8);
    out[3] = (unsigned char)tot;
    uint16_t ipid = (uint16_t)(prng32(rng) >> 16);
    out[4] = (unsigned char)(ipid >> 8);
    out[5] = (unsigned char)ipid;
    out[8] = 64;
    out[9] = IPPROTO_TCP;
    memcpy(out + 12, sip, 4);
    memcpy(out + 16, dip, 4);
    if (ip_opt_len != 0)
      memcpy(out + 20, ip_opts, ip_opt_len);
    unsigned io = ip_hlen;
    uint32_t seq = prng32(rng);
    out[io + 0] = (unsigned char)(sport >> 8);
    out[io + 1] = (unsigned char)sport;
    out[io + 2] = (unsigned char)(dport >> 8);
    out[io + 3] = (unsigned char)dport;
    out[io + 4] = (unsigned char)(seq >> 24);
    out[io + 5] = (unsigned char)(seq >> 16);
    out[io + 6] = (unsigned char)(seq >> 8);
    out[io + 7] = (unsigned char)seq;
    out[io + 12] = (unsigned char)((tcp_total / 4u) << 4);
    out[io + 13] = TH_SYN;
    out[io + 14] = (unsigned char)(tcp_win >> 8);
    out[io + 15] = (unsigned char)tcp_win;
    if (tcp_opt_len != 0)
      memcpy(out + io + 20, tcp_opts, tcp_opt_len);
    for (unsigned i = 0; i < payload_len; i++)
      out[io + tcp_total + i] = (unsigned char)(prng32(rng) & 0xff);
    return (int)tot;
  }

  return -1;
}

/* Locate IPv4 datagram inside a captured frame; returns 0 on success. */
static int nfuzz_pcap_frame_to_ipv4(int dlt, const unsigned char *data,
    unsigned caplen, const unsigned char **ip, unsigned *ip_len)
{
  const unsigned char *p = data;
  unsigned left = caplen;

  if (dlt == DLT_EN10MB) {
    if (left < 14)
      return -1;
    size_t off = 12;
    uint16_t et = (uint16_t)((p[off] << 8) | p[off + 1]);
    off = 14;
    if (et == 0x8100) {
      if (left < 18)
        return -1;
      et = (uint16_t)((p[16] << 8) | p[17]);
      off = 18;
    }
    if (et != 0x0800)
      return -1;
    p += off;
    left -= (unsigned)off;
  } else if (dlt == DLT_RAW) {
    /* raw IP */
  } else if (dlt == DLT_NULL || dlt == DLT_LOOP) {
    if (left < 4 + 20)
      return -1;
    uint32_t af;
    memcpy(&af, p, sizeof(af));
    /* BSD: AF_INET = 2 in host order; Linux loopback often LE 2 */
    if (af != 2u && af != (uint32_t)htonl(2))
      return -1;
    p += 4;
    left -= 4;
  } else if (dlt == DLT_LINUX_SLL) {
    if (left < 16)
      return -1;
    uint16_t et = (uint16_t)((p[14] << 8) | p[15]);
    if (et != 0x0800)
      return -1;
    p += 16;
    left -= 16;
  } else {
    return -1;
  }

  if (left < 20 || (p[0] >> 4) != 4)
    return -1;
  unsigned ihl = (unsigned)(p[0] & 0x0fu) * 4u;
  if (ihl < 20 || ihl > left)
    return -1;
  int tot = (int)((p[2] << 8) | p[3]);
  if (tot < (int)ihl)
    return -1;
  if (tot > (int)left)
    tot = (int)left;
  *ip = p;
  *ip_len = (unsigned)tot;
  return 0;
}

/*
 * Load Nth IPv4 packet from pcap (1-based index). Supports Ethernet (incl. 802.1Q),
 * DLT_RAW, DLT_NULL/DLT_LOOP, Linux cooked (SLL).
 */
static int nfuzz_pcap_load_ipv4(const char *path, long which,
    unsigned char *out, int outmax)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pch;

  if (which < 1) {
    fprintf(stderr, "nfuzz: --pcap-index must be >= 1\n");
    return -1;
  }

  pch = pcap_open_offline(path, errbuf);
  if (pch == NULL) {
    fprintf(stderr, "nfuzz: pcap_open_offline %s: %s\n", path, errbuf);
    return -1;
  }

  int dlt = pcap_datalink(pch);
  long seen = 0;
  struct pcap_pkthdr *hdr;
  const u_char *pkt;
  int rc;
  int out_len = -1;

  while ((rc = pcap_next_ex(pch, &hdr, &pkt)) == 1) {
    const unsigned char *ip;
    unsigned iplen;

    if (hdr->caplen == 0)
      continue;
    if (nfuzz_pcap_frame_to_ipv4(dlt, pkt, hdr->caplen, &ip, &iplen) != 0)
      continue;
    if ((int)iplen < 20 || (int)iplen > outmax)
      continue;
    seen++;
    if (seen < which)
      continue;
    memcpy(out, ip, iplen);
    out_len = (int)iplen;
    break;
  }

  if (rc == -1) {
    fprintf(stderr, "nfuzz: pcap read error: %s\n", pcap_geterr(pch));
    pcap_close(pch);
    return -1;
  }

  pcap_close(pch);

  if (out_len < 0) {
    fprintf(stderr,
        "nfuzz: no IPv4 packet #%ld in %s (datalink=%d)\n", which, path, dlt);
    return -1;
  }
  return out_len;
}

/* If mtu>0 and len > mtu, split IPv4 payload into fragments (RFC 791 style). */
static int ipv4_send_with_frag_mtu(int fd, const unsigned char *pkt, int len,
    struct sockaddr_in *dst, unsigned mtu, uint32_t *rng)
{
  if (mtu == 0) {
    ssize_t sent = sendto(fd, pkt, (size_t)len, 0, (struct sockaddr *)dst,
        sizeof(*dst));
    if (sent < 0) {
      fprintf(stderr, "nfuzz: sendto: %s\n", strerror(errno));
      return -1;
    }
    return 0;
  }

  unsigned ihl = ip_header_len(pkt, len);
  if (ihl < 20 || (int)ihl >= len) {
    fprintf(stderr, "nfuzz: invalid IPv4 header for fragmentation\n");
    return -1;
  }
  if (mtu < ihl + 8) {
    fprintf(stderr, "nfuzz: --frag-mtu too small (need at least IP header + 8)\n");
    return -1;
  }

  int payload_len = len - (int)ihl;
  if (payload_len <= 0) {
    fprintf(stderr, "nfuzz: no payload to send\n");
    return -1;
  }

  if ((unsigned)len <= mtu) {
    ssize_t sent = sendto(fd, pkt, (size_t)len, 0, (struct sockaddr *)dst,
        sizeof(*dst));
    if (sent < 0) {
      fprintf(stderr, "nfuzz: sendto: %s\n", strerror(errno));
      return -1;
    }
    return 0;
  }

  unsigned chunk_max = (mtu - ihl) / 8u * 8u;
  if (chunk_max == 0) {
    fprintf(stderr, "nfuzz: --frag-mtu leaves no room for payload\n");
    return -1;
  }

  uint16_t ident = (uint16_t)((pkt[4] << 8) | pkt[5]);
  if (ident == 0)
    ident = (uint16_t)(prng32(rng) >> 16);

  unsigned char frag[NFUZZ_MAX_PACKET];
  int off = 0;
  while (off < payload_len) {
    int remaining = payload_len - off;
    int chunk;
    int more;
    if (remaining <= (int)chunk_max) {
      chunk = remaining;
      more = 0;
    } else {
      chunk = (int)chunk_max;
      chunk -= chunk % 8;
      if (chunk <= 0) {
        fprintf(stderr, "nfuzz: fragmentation stuck (try larger --frag-mtu)\n");
        return -1;
      }
      more = 1;
    }
    int frag_len = (int)ihl + chunk;
    if (frag_len > (int)sizeof(frag)) {
      fprintf(stderr, "nfuzz: fragment exceeds buffer\n");
      return -1;
    }
    memcpy(frag, pkt, ihl);
    memcpy(frag + ihl, pkt + ihl + (size_t)off, (size_t)chunk);
    frag[4] = (unsigned char)(ident >> 8);
    frag[5] = (unsigned char)ident;
    uint16_t fo = (uint16_t)((unsigned)off / 8u);
    if (more)
      fo = (uint16_t)(fo | (uint16_t)NFUZZ_IP_MF);
    frag[6] = (unsigned char)(fo >> 8);
    frag[7] = (unsigned char)fo;
    frag[2] = (unsigned char)((frag_len >> 8) & 0xff);
    frag[3] = (unsigned char)(frag_len & 0xff);
    frag[10] = frag[11] = 0;
    uint16_t c = in_cksum(frag, ihl);
    frag[10] = (unsigned char)((c >> 8) & 0xff);
    frag[11] = (unsigned char)(c & 0xff);

    ssize_t sent = sendto(fd, frag, (size_t)frag_len, 0,
        (struct sockaddr *)dst, sizeof(*dst));
    if (sent < 0) {
      fprintf(stderr, "nfuzz: sendto (frag): %s\n", strerror(errno));
      return -1;
    }
    off += chunk;
  }
  return 0;
}

static uint32_t prng32(uint32_t *s)
{
  *s = *s * 1664525u + 1013904223u;
  return *s;
}

static void mutate_bitflip(unsigned char *buf, int off, int mlen, uint32_t *seed)
{
  if (mlen <= 0)
    return;
  int i = off + (int)(prng32(seed) % (unsigned)mlen);
  unsigned bit = 1u << (prng32(seed) % 8);
  buf[i] ^= (unsigned char)bit;
}

static void mutate_random_byte(unsigned char *buf, int off, int mlen, uint32_t *seed)
{
  if (mlen <= 0)
    return;
  int i = off + (int)(prng32(seed) % (unsigned)mlen);
  buf[i] = (unsigned char)(prng32(seed) & 0xff);
}

static void mutate_inc_byte(unsigned char *buf, int off, int mlen, uint32_t *seed)
{
  if (mlen <= 0)
    return;
  int i = off + (int)(prng32(seed) % (unsigned)mlen);
  buf[i] = (unsigned char)(buf[i] + 1u);
}

static void mutate_dec_byte(unsigned char *buf, int off, int mlen, uint32_t *seed)
{
  if (mlen <= 0)
    return;
  int i = off + (int)(prng32(seed) % (unsigned)mlen);
  buf[i] = (unsigned char)(buf[i] - 1u);
}

/* Truncate packet at end; returns new length */
static int mutate_truncate(unsigned char *buf, int len, int off, int mlen, uint32_t *seed)
{
  (void)buf;
  if (mlen <= 0 || len <= off + 1)
    return len;
  int maxcut = len - off - 1;
  int cut = 1 + (int)(prng32(seed) % (unsigned)maxcut);
  return len - cut;
}

/* Append random bytes at end; returns new length */
static int mutate_append(unsigned char *buf, int len, uint32_t *seed)
{
  int n = 1 + (int)(prng32(seed) % 64);
  if (len + n > NFUZZ_MAX_PACKET)
    n = NFUZZ_MAX_PACKET - len;
  if (n <= 0)
    return len;
  for (int i = 0; i < n; i++)
    buf[len + i] = (unsigned char)(prng32(seed) & 0xff);
  return len + n;
}

static void mutate_shuffle_block(unsigned char *buf, int off, int mlen, uint32_t *seed)
{
  if (mlen < 2)
    return;
  int blen = 2 + (int)(prng32(seed) % (unsigned)(mlen - 1));
  int start = off + (int)(prng32(seed) % (unsigned)(mlen - blen + 1));
  for (int i = 0; i < blen / 2; i++) {
    unsigned char t = buf[start + i];
    buf[start + i] = buf[start + blen - 1 - i];
    buf[start + blen - 1 - i] = t;
  }
}

/* Application payload for --proto / --bt-l2cap (not raw IPv4). */
static int load_stream_base_payload(unsigned char *out, int outmax,
    const char *hex_file, const char *hex_arg, size_t user_len, int user_explicit)
{
  if (hex_file != NULL)
    return read_hex_file(hex_file, out, outmax);
  if (hex_arg != NULL) {
    int n = decode_hex_buffer(hex_arg, strlen(hex_arg), out, outmax);
    return n;
  }
  size_t len = user_explicit ? user_len : (size_t)NFUZZ_PROTO_DEFAULT_PAYLOAD;
  if (len > (size_t)outmax) {
    fprintf(stderr, "nfuzz: stream payload length too large (max %d)\n", outmax);
    return -1;
  }
  memset(out, 0, len);
  return (int)len;
}

static int apply_payload_mutation(unsigned char *work, int len, int bufmax,
    const char *strategy, long mut_off, long mut_len, uint32_t *rng)
{
  int moff = mut_off >= 0 ? (int)mut_off : 0;
  int mlen = mut_len >= 0 ? (int)mut_len : (len - moff);
  if (moff < 0 || moff > len || mlen < 0 || moff + mlen > len) {
    fprintf(stderr, "nfuzz: stream/bt: invalid mutable region\n");
    return -1;
  }
  if (strcasecmp(strategy, "bitflip") == 0)
    mutate_bitflip(work, moff, mlen, rng);
  else if (strcasecmp(strategy, "random_byte") == 0)
    mutate_random_byte(work, moff, mlen, rng);
  else if (strcasecmp(strategy, "inc_byte") == 0)
    mutate_inc_byte(work, moff, mlen, rng);
  else if (strcasecmp(strategy, "dec_byte") == 0)
    mutate_dec_byte(work, moff, mlen, rng);
  else if (strcasecmp(strategy, "truncate") == 0)
    len = mutate_truncate(work, len, moff, mlen, rng);
  else if (strcasecmp(strategy, "append_random") == 0)
    len = mutate_append(work, len, rng);
  else if (strcasecmp(strategy, "shuffle_block") == 0)
    mutate_shuffle_block(work, moff, mlen, rng);
  else {
    fprintf(stderr, "nfuzz: unknown strategy %s\n", strategy);
    return -1;
  }
  if (len < 1)
    len = 1;
  if (len > bufmax)
    len = bufmax;
  return len;
}

static int tcp_connect_with_timeout(struct in_addr *dst, uint16_t port, int timeout_sec)
{
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("nfuzz: socket(tcp)");
    return -1;
  }
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) {
    perror("nfuzz: fcntl(tcp)");
    close(fd);
    return -1;
  }
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr = *dst;
  int cr = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
  if (cr < 0 && errno != EINPROGRESS) {
    fprintf(stderr, "nfuzz: connect: %s\n", strerror(errno));
    close(fd);
    return -1;
  }
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLOUT;
  int pr = poll(&pfd, 1, timeout_sec * 1000);
  if (pr <= 0) {
    fprintf(stderr, "nfuzz: tcp connect timed out or failed\n");
    close(fd);
    return -1;
  }
  int soerr = 0;
  socklen_t sl = sizeof(soerr);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0) {
    fprintf(stderr, "nfuzz: tcp connect error: %s\n",
        soerr != 0 ? strerror(soerr) : "getsockopt");
    close(fd);
    return -1;
  }
  if (fcntl(fd, F_SETFL, fl) != 0) {
    perror("nfuzz: fcntl(tcp clear nonblock)");
    close(fd);
    return -1;
  }
#ifdef SO_NOSIGPIPE
  {
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
  }
#endif
  return fd;
}

static int run_proto_stream_fuzz(struct in_addr *dst, uint16_t dport, int use_tcp,
    unsigned char *template, int tlen, unsigned long count, unsigned rate,
    const char *strategy, long mut_off, long mut_len, long seed_arg,
    int proto_reconnect, int connect_to_sec)
{
  uint32_t rng = (uint32_t)(seed_arg >= 0 ? seed_arg : (long)time(NULL) ^ (long)now_ns());
  if (rng == 0)
    rng = 0xcafebabeu;
  unsigned char work[NFUZZ_MAX_PACKET];
  unsigned long interval_ns = rate > 0 ? 1000000000UL / rate : 0;
  int tfd = -1;

  if (!use_tcp) {
    tfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (tfd < 0) {
      perror("nfuzz: socket(udp)");
      return 1;
    }
  } else if (!proto_reconnect) {
    tfd = tcp_connect_with_timeout(dst, dport, connect_to_sec);
    if (tfd < 0)
      return 1;
  }

  struct sockaddr_in peer;
  memset(&peer, 0, sizeof(peer));
  peer.sin_family = AF_INET;
  peer.sin_port = htons(dport);
  peer.sin_addr = *dst;

  for (unsigned long n = 0; n < count; n++) {
    if (use_tcp && proto_reconnect) {
      if (tfd >= 0)
        close(tfd);
      tfd = tcp_connect_with_timeout(dst, dport, connect_to_sec);
      if (tfd < 0)
        return 1;
    }

    memcpy(work, template, (size_t)tlen);
    int len = tlen;
    len = apply_payload_mutation(work, len, NFUZZ_MAX_PACKET, strategy, mut_off,
        mut_len, &rng);
    if (len < 0)
      goto fail;

    if (use_tcp) {
      size_t off = 0;
      while (off < (size_t)len) {
        ssize_t sent = send(tfd, work + off, (size_t)len - off, MSG_NOSIGNAL);
        if (sent <= 0) {
          fprintf(stderr, "nfuzz: send(tcp): %s\n",
              sent < 0 ? strerror(errno) : "closed");
          goto fail;
        }
        off += (size_t)sent;
      }
    } else {
      ssize_t sent = sendto(tfd, work, (size_t)len, 0, (struct sockaddr *)&peer,
          sizeof(peer));
      if (sent < 0) {
        perror("nfuzz: sendto(udp)");
        goto fail;
      }
    }

    if (rate > 0 && interval_ns > 0) {
      struct timespec sl;
      sl.tv_sec = (time_t)(interval_ns / 1000000000UL);
      sl.tv_nsec = (long)(interval_ns % 1000000000UL);
      nanosleep(&sl, NULL);
    }
  }

  if (tfd >= 0)
    close(tfd);
  fprintf(stderr, "nfuzz: sent %lu stream payload(s)\n", count);
  return 0;

fail:
  if (tfd >= 0)
    close(tfd);
  return 1;
}

#ifdef HAVE_BLUETOOTH_L2CAP
static int run_bt_l2cap_fuzz(const char *bdstr, uint16_t psm_host_order,
    unsigned char *template, int tlen, unsigned long count, unsigned rate,
    const char *strategy, long mut_off, long mut_len, long seed_arg)
{
  uint32_t rng = (uint32_t)(seed_arg >= 0 ? seed_arg : (long)time(NULL) ^ (long)now_ns());
  if (rng == 0)
    rng = 0xbaddc0deu;
  unsigned char work[NFUZZ_MAX_PACKET];
  unsigned long interval_ns = rate > 0 ? 1000000000UL / rate : 0;

#ifdef __APPLE__
  void *bt = NULL;
  int o = nfuzz_bt_mac_open(bdstr, psm_host_order, &bt);
  if (o == -1) {
    fprintf(stderr, "nfuzz: bad Bluetooth address (use XX:XX:XX:XX:XX:XX)\n");
    return 2;
  }
  if (o != 0 || bt == NULL) {
    fprintf(stderr, "nfuzz: L2CAP connect failed (is the peer paired/in range?)\n");
    return 1;
  }
  for (unsigned long n = 0; n < count; n++) {
    memcpy(work, template, (size_t)tlen);
    int len = tlen;
    len = apply_payload_mutation(work, len, NFUZZ_MAX_PACKET, strategy, mut_off,
        mut_len, &rng);
    if (len < 0) {
      nfuzz_bt_mac_close(bt);
      return 1;
    }
    if (nfuzz_bt_mac_send(bt, work, len) != 0) {
      fprintf(stderr, "nfuzz: l2cap send failed\n");
      nfuzz_bt_mac_close(bt);
      return 1;
    }
    if (rate > 0 && interval_ns > 0) {
      struct timespec sl;
      sl.tv_sec = (time_t)(interval_ns / 1000000000UL);
      sl.tv_nsec = (long)(interval_ns % 1000000000UL);
      nanosleep(&sl, NULL);
    }
  }
  nfuzz_bt_mac_close(bt);
#else
  bdaddr_t ba;
  if (str2ba(bdstr, &ba) < 0) {
    fprintf(stderr, "nfuzz: bad Bluetooth address (use XX:XX:XX:XX:XX:XX)\n");
    return 2;
  }
  int s = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
  if (s < 0) {
    perror("nfuzz: socket(BT_L2CAP)");
    return 1;
  }
  struct sockaddr_l2 addr;
  memset(&addr, 0, sizeof(addr));
  addr.l2_family = AF_BLUETOOTH;
  addr.l2_bdaddr = ba;
  addr.l2_psm = htobs(psm_host_order);
  if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("nfuzz: l2cap connect");
    close(s);
    return 1;
  }

  for (unsigned long n = 0; n < count; n++) {
    memcpy(work, template, (size_t)tlen);
    int len = tlen;
    len = apply_payload_mutation(work, len, NFUZZ_MAX_PACKET, strategy, mut_off,
        mut_len, &rng);
    if (len < 0) {
      close(s);
      return 1;
    }
    ssize_t w = send(s, work, (size_t)len, 0);
    if (w < 0) {
      perror("nfuzz: l2cap send");
      close(s);
      return 1;
    }
    if (rate > 0 && interval_ns > 0) {
      struct timespec sl;
      sl.tv_sec = (time_t)(interval_ns / 1000000000UL);
      sl.tv_nsec = (long)(interval_ns % 1000000000UL);
      nanosleep(&sl, NULL);
    }
  }
  close(s);
#endif
  fprintf(stderr, "nfuzz: sent %lu L2CAP payload(s)\n", count);
  return 0;
}
#endif /* HAVE_BLUETOOTH_L2CAP */

static int parse_inaddr(const char *s, struct in_addr *out)
{
  return inet_pton(AF_INET, s, out) == 1 ? 0 : -1;
}

static uint32_t now_ns(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return 0;
  return (uint32_t)(ts.tv_sec * 1000000000ULL + ts.tv_nsec);
}

int main(int argc, char **argv)
{
  int authorized = (getenv("NFUZZ_AUTHORIZED") != NULL
      && strcmp(getenv("NFUZZ_AUTHORIZED"), "1") == 0) ? 1 : 0;

  int http_daemon = 0;
  const char *http_bind = NFUZZ_HTTP_DEFAULT_BIND;
  size_t http_max_body = NFUZZ_HTTP_DEFAULT_MAX_BODY;
  unsigned http_refresh = NFUZZ_HTTP_DEFAULT_REFRESH;
  int http_allow_remote = 0;
  int do_detach = 0;
  const char *pid_file = NULL;

  struct nfuzz_http_browser_opts brw;
  char *browser_extra_argv[NFUZZ_BROWSER_MAX_EXTRA];
  memset(&brw, 0, sizeof(brw));
  brw.browser_preset = 0;
  brw.browser_extra = browser_extra_argv;

  const char *hex_file = NULL;
  const char *hex_arg = NULL;
  const char *dst_str = NULL;
  const char *src_str = NULL;
  int patch_addresses = 0;
  unsigned long count = 1;
  unsigned rate = 0;
  long seed_arg = -1;
  const char *strategy = "bitflip";
  long mut_off = -1;
  long mut_len = -1;
  int fix_ip_len = 1;
  int fix_csum = 1;
  int fix_l4 = 0;
  const char *template_name = NULL;
  uint16_t tpl_sport = 0;
  uint16_t tpl_dport = 0;
  unsigned tpl_payload_len = 0;
  unsigned tpl_icmp_id = 1;
  unsigned tpl_icmp_seq = 0;
  uint16_t tpl_tcp_win = 0;
  unsigned frag_mtu = 0;
  const char *pcap_file = NULL;
  long pcap_index = 1;
  const char *ip_opt_hex = NULL;
  const char *tcp_opt_hex = NULL;
  unsigned tcp_mss = 0;
  int proto_mode = 0; /* 0=off, 1=tcp, 2=udp */
  size_t proto_payload_len = 0;
  int proto_payload_explicit = 0;
  int proto_reconnect = 0;
  int proto_connect_to = 10;
  const char *bt_l2cap_str = NULL;
#ifdef HAVE_BLUETOOTH_L2CAP
  unsigned bt_psm = 0;
#endif

  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    if (strcmp(a, "--authorized") == 0) {
      authorized = 1;
    } else if (strcmp(a, "--http-daemon") == 0) {
      http_daemon = 1;
    } else if (strncmp(a, "--http-bind=", 12) == 0) {
      http_bind = a + 12;
    } else if (strcmp(a, "--http-bind") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      http_bind = argv[i];
    } else if (strncmp(a, "--http-max-body=", 16) == 0) {
      http_max_body = (size_t)strtoul(a + 16, NULL, 10);
    } else if (strcmp(a, "--http-max-body") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      http_max_body = (size_t)strtoul(argv[i], NULL, 10);
    } else if (strncmp(a, "--http-refresh=", 15) == 0) {
      http_refresh = (unsigned)strtoul(a + 15, NULL, 10);
    } else if (strcmp(a, "--http-refresh") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      http_refresh = (unsigned)strtoul(argv[i], NULL, 10);
    } else if (strcmp(a, "--http-allow-remote") == 0) {
      http_allow_remote = 1;
    } else if (strcmp(a, "--auto-browser") == 0) {
      brw.auto_browser = 1;
    } else if (strncmp(a, "--browser-cmd=", 14) == 0) {
      brw.browser_cmd = a + 14;
    } else if (strcmp(a, "--browser-cmd") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      brw.browser_cmd = argv[i];
    } else if (strncmp(a, "--browser-preset=", 17) == 0) {
      const char *p = a + 17;
      if (strcasecmp(p, "chromium") == 0)
        brw.browser_preset = 0;
      else if (strcasecmp(p, "firefox") == 0)
        brw.browser_preset = 1;
      else if (strcasecmp(p, "none") == 0)
        brw.browser_preset = 2;
      else {
        fprintf(stderr,
            "nfuzz: --browser-preset must be chromium, firefox, or none\n");
        return 2;
      }
    } else if (strcmp(a, "--browser-preset") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      const char *p = argv[i];
      if (strcasecmp(p, "chromium") == 0)
        brw.browser_preset = 0;
      else if (strcasecmp(p, "firefox") == 0)
        brw.browser_preset = 1;
      else if (strcasecmp(p, "none") == 0)
        brw.browser_preset = 2;
      else {
        fprintf(stderr,
            "nfuzz: --browser-preset must be chromium, firefox, or none\n");
        return 2;
      }
    } else if (strncmp(a, "--browser-restart-sec=", 21) == 0) {
      brw.browser_restart_sec = (unsigned)strtoul(a + 21, NULL, 10);
    } else if (strcmp(a, "--browser-restart-sec") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      brw.browser_restart_sec = (unsigned)strtoul(argv[i], NULL, 10);
    } else if (strncmp(a, "--browser-url=", 14) == 0) {
      brw.browser_url_override = a + 14;
    } else if (strcmp(a, "--browser-url") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      brw.browser_url_override = argv[i];
    } else if (strncmp(a, "--browser-arg=", 14) == 0) {
      if (brw.browser_extra_n >= NFUZZ_BROWSER_MAX_EXTRA) {
        fprintf(stderr, "nfuzz: too many --browser-arg (max %d)\n",
            NFUZZ_BROWSER_MAX_EXTRA);
        return 2;
      }
      brw.browser_extra[brw.browser_extra_n++] = (char *)(a + 14);
    } else if (strcmp(a, "--browser-arg") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      if (brw.browser_extra_n >= NFUZZ_BROWSER_MAX_EXTRA) {
        fprintf(stderr, "nfuzz: too many --browser-arg (max %d)\n",
            NFUZZ_BROWSER_MAX_EXTRA);
        return 2;
      }
      brw.browser_extra[brw.browser_extra_n++] = argv[i];
    } else if (strcmp(a, "--detach") == 0) {
      do_detach = 1;
    } else if (strncmp(a, "--pid-file=", 11) == 0) {
      pid_file = a + 11;
    } else if (strcmp(a, "--pid-file") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      pid_file = argv[i];
    } else if (strncmp(a, "--hex-file=", 11) == 0) {
      hex_file = a + 11;
    } else if (strcmp(a, "--hex-file") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      hex_file = argv[i];
    } else if (strncmp(a, "--hex=", 6) == 0) {
      hex_arg = a + 6;
    } else if (strcmp(a, "--hex") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      hex_arg = argv[i];
    } else if (strncmp(a, "--template=", 11) == 0) {
      template_name = a + 11;
    } else if (strcmp(a, "--template") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      template_name = argv[i];
    } else if (strncmp(a, "--sport=", 8) == 0) {
      unsigned long v = strtoul(a + 8, NULL, 10);
      if (v > 65535) {
        fprintf(stderr, "nfuzz: --sport out of range\n");
        return 2;
      }
      tpl_sport = (uint16_t)v;
    } else if (strcmp(a, "--sport") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      unsigned long v = strtoul(argv[i], NULL, 10);
      if (v > 65535) {
        fprintf(stderr, "nfuzz: --sport out of range\n");
        return 2;
      }
      tpl_sport = (uint16_t)v;
    } else if (strncmp(a, "--dport=", 8) == 0) {
      unsigned long v = strtoul(a + 8, NULL, 10);
      if (v > 65535) {
        fprintf(stderr, "nfuzz: --dport out of range\n");
        return 2;
      }
      tpl_dport = (uint16_t)v;
    } else if (strcmp(a, "--dport") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      unsigned long v = strtoul(argv[i], NULL, 10);
      if (v > 65535) {
        fprintf(stderr, "nfuzz: --dport out of range\n");
        return 2;
      }
      tpl_dport = (uint16_t)v;
    } else if (strncmp(a, "--payload-len=", 14) == 0) {
      tpl_payload_len = (unsigned)strtoul(a + 14, NULL, 10);
    } else if (strcmp(a, "--payload-len") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      tpl_payload_len = (unsigned)strtoul(argv[i], NULL, 10);
    } else if (strncmp(a, "--icmp-id=", 10) == 0) {
      tpl_icmp_id = (unsigned)strtoul(a + 10, NULL, 10);
    } else if (strcmp(a, "--icmp-id") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      tpl_icmp_id = (unsigned)strtoul(argv[i], NULL, 10);
    } else if (strncmp(a, "--icmp-seq=", 11) == 0) {
      tpl_icmp_seq = (unsigned)strtoul(a + 11, NULL, 10);
    } else if (strcmp(a, "--icmp-seq") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      tpl_icmp_seq = (unsigned)strtoul(argv[i], NULL, 10);
    } else if (strncmp(a, "--tcp-win=", 10) == 0) {
      unsigned long v = strtoul(a + 10, NULL, 10);
      if (v > 65535) {
        fprintf(stderr, "nfuzz: --tcp-win out of range\n");
        return 2;
      }
      tpl_tcp_win = (uint16_t)v;
    } else if (strcmp(a, "--tcp-win") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      unsigned long v = strtoul(argv[i], NULL, 10);
      if (v > 65535) {
        fprintf(stderr, "nfuzz: --tcp-win out of range\n");
        return 2;
      }
      tpl_tcp_win = (uint16_t)v;
    } else if (strncmp(a, "--frag-mtu=", 11) == 0) {
      frag_mtu = (unsigned)strtoul(a + 11, NULL, 10);
    } else if (strcmp(a, "--frag-mtu") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      frag_mtu = (unsigned)strtoul(argv[i], NULL, 10);
    } else if (strncmp(a, "--pcap=", 7) == 0) {
      pcap_file = a + 7;
    } else if (strcmp(a, "--pcap") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      pcap_file = argv[i];
    } else if (strncmp(a, "--pcap-index=", 13) == 0) {
      pcap_index = strtol(a + 13, NULL, 10);
    } else if (strcmp(a, "--pcap-index") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      pcap_index = strtol(argv[i], NULL, 10);
    } else if (strncmp(a, "--ip-options-hex=", 17) == 0) {
      ip_opt_hex = a + 17;
    } else if (strcmp(a, "--ip-options-hex") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      ip_opt_hex = argv[i];
    } else if (strncmp(a, "--tcp-options-hex=", 18) == 0) {
      tcp_opt_hex = a + 18;
    } else if (strcmp(a, "--tcp-options-hex") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      tcp_opt_hex = argv[i];
    } else if (strncmp(a, "--tcp-mss=", 10) == 0) {
      tcp_mss = (unsigned)strtoul(a + 10, NULL, 10);
    } else if (strcmp(a, "--tcp-mss") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      tcp_mss = (unsigned)strtoul(argv[i], NULL, 10);
    } else if (strncmp(a, "--proto=", 8) == 0) {
      const char *p = a + 8;
      if (strcasecmp(p, "tcp") == 0)
        proto_mode = 1;
      else if (strcasecmp(p, "udp") == 0)
        proto_mode = 2;
      else {
        fprintf(stderr, "nfuzz: --proto must be tcp or udp\n");
        return 2;
      }
    } else if (strcmp(a, "--proto") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      const char *p = argv[i];
      if (strcasecmp(p, "tcp") == 0)
        proto_mode = 1;
      else if (strcasecmp(p, "udp") == 0)
        proto_mode = 2;
      else {
        fprintf(stderr, "nfuzz: --proto must be tcp or udp\n");
        return 2;
      }
    } else if (strncmp(a, "--proto-payload-len=", 20) == 0) {
      proto_payload_len = (size_t)strtoul(a + 20, NULL, 10);
      proto_payload_explicit = 1;
    } else if (strcmp(a, "--proto-payload-len") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      proto_payload_len = (size_t)strtoul(argv[i], NULL, 10);
      proto_payload_explicit = 1;
    } else if (strcmp(a, "--proto-reconnect") == 0) {
      proto_reconnect = 1;
    } else if (strncmp(a, "--proto-connect-timeout=", 24) == 0) {
      proto_connect_to = (int)strtol(a + 24, NULL, 10);
    } else if (strcmp(a, "--proto-connect-timeout") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      proto_connect_to = (int)strtol(argv[i], NULL, 10);
    } else if (strncmp(a, "--bt-l2cap=", 11) == 0) {
      bt_l2cap_str = a + 11;
    } else if (strcmp(a, "--bt-l2cap") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      bt_l2cap_str = argv[i];
    } else if (strncmp(a, "--bt-psm=", 9) == 0) {
#ifdef HAVE_BLUETOOTH_L2CAP
      unsigned long v = strtoul(a + 9, NULL, 10);
      if (v > 65535) {
        fprintf(stderr, "nfuzz: --bt-psm out of range\n");
        return 2;
      }
      bt_psm = (unsigned)v;
#else
      fprintf(stderr,
          "nfuzz: --bt-psm is not available in this build "
          "(need macOS or Linux with libbluetooth)\n");
      return 2;
#endif
    } else if (strcmp(a, "--bt-psm") == 0) {
#ifdef HAVE_BLUETOOTH_L2CAP
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      unsigned long v = strtoul(argv[i], NULL, 10);
      if (v > 65535) {
        fprintf(stderr, "nfuzz: --bt-psm out of range\n");
        return 2;
      }
      bt_psm = (unsigned)v;
#else
      fprintf(stderr,
          "nfuzz: --bt-psm is not available in this build "
          "(need macOS or Linux with libbluetooth)\n");
      return 2;
#endif
    } else if (strncmp(a, "--dst=", 6) == 0) {
      dst_str = a + 6;
    } else if (strcmp(a, "--dst") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      dst_str = argv[i];
    } else if (strncmp(a, "--src=", 6) == 0) {
      src_str = a + 6;
    } else if (strcmp(a, "--src") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      src_str = argv[i];
    } else if (strcmp(a, "--patch-addresses") == 0) {
      patch_addresses = 1;
    } else if (strcmp(a, "--fix-ip-len") == 0) {
      fix_ip_len = 1;
    } else if (strcmp(a, "--no-fix-ip-len") == 0) {
      fix_ip_len = 0;
    } else if (strcmp(a, "--fix-checksums") == 0) {
      fix_csum = 1;
    } else if (strcmp(a, "--no-fix-checksums") == 0) {
      fix_csum = 0;
    } else if (strcmp(a, "--fix-l4") == 0) {
      fix_l4 = 1;
    } else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
      usage(stdout, argv[0]);
      return 0;
    } else if (strcmp(a, "--version") == 0 || strcmp(a, "-V") == 0) {
      puts(version_string());
      return 0;
    } else if (strcmp(a, "-c") == 0 || strcmp(a, "--count") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      count = strtoul(argv[i], NULL, 10);
    } else if (strncmp(a, "--count=", 8) == 0) {
      count = strtoul(a + 8, NULL, 10);
    } else if (strcmp(a, "-r") == 0 || strcmp(a, "--rate") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      rate = (unsigned)strtoul(argv[i], NULL, 10);
    } else if (strncmp(a, "--rate=", 7) == 0) {
      rate = (unsigned)strtoul(a + 7, NULL, 10);
    } else if (strcmp(a, "-s") == 0 || strcmp(a, "--seed") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      seed_arg = strtol(argv[i], NULL, 10);
    } else if (strncmp(a, "--seed=", 7) == 0) {
      seed_arg = strtol(a + 7, NULL, 10);
    } else if (strcmp(a, "-S") == 0 || strcmp(a, "--strategy") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      strategy = argv[i];
    } else if (strncmp(a, "--strategy=", 11) == 0) {
      strategy = a + 11;
    } else if (strcmp(a, "-m") == 0 || strcmp(a, "--mutable-off") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      mut_off = strtol(argv[i], NULL, 10);
    } else if (strncmp(a, "--mutable-off=", 14) == 0) {
      mut_off = strtol(a + 14, NULL, 10);
    } else if (strcmp(a, "-l") == 0 || strcmp(a, "--mutable-len") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "nfuzz: missing value after %s\n", a);
        return 2;
      }
      mut_len = strtol(argv[i], NULL, 10);
    } else if (strncmp(a, "--mutable-len=", 14) == 0) {
      mut_len = strtol(a + 14, NULL, 10);
    } else if (a[0] == '-') {
      fprintf(stderr, "nfuzz: unknown option: %s\n", a);
      return 2;
    } else {
      fprintf(stderr, "nfuzz: unexpected argument: %s\n", a);
      return 2;
    }
  }

  if (!authorized) {
    fprintf(stderr,
        "nfuzz: refusing to run without --authorized or NFUZZ_AUTHORIZED=1\n");
    return 2;
  }

  if ((do_detach || pid_file) && !http_daemon) {
    fprintf(stderr,
        "nfuzz: --detach and --pid-file require --http-daemon\n");
    return 2;
  }

  if (http_refresh > 86400u) {
    fprintf(stderr, "nfuzz: --http-refresh too large (max 86400)\n");
    return 2;
  }

  if (brw.auto_browser && !http_daemon) {
    fprintf(stderr, "nfuzz: --auto-browser requires --http-daemon\n");
    return 2;
  }

  if (brw.browser_restart_sec > 86400u) {
    fprintf(stderr, "nfuzz: --browser-restart-sec too large (max 86400)\n");
    return 2;
  }

  if (http_daemon) {
    return run_http_daemon(http_bind, http_max_body, http_refresh, do_detach,
        pid_file, http_allow_remote, seed_arg, &brw);
  }

  int have_bt = (bt_l2cap_str != NULL);
#ifndef HAVE_BLUETOOTH_L2CAP
  if (have_bt) {
    fprintf(stderr,
        "nfuzz: --bt-l2cap is not available in this build "
        "(need macOS or Linux with libbluetooth)\n");
    return 2;
  }
#endif
  int stream_or_bt = (proto_mode != 0) || have_bt;
  if (stream_or_bt) {
    if (template_name != NULL || pcap_file != NULL || frag_mtu != 0
        || patch_addresses || src_str != NULL || ip_opt_hex != NULL
        || tcp_opt_hex != NULL || tcp_mss > 0) {
      fprintf(stderr,
          "nfuzz: --proto/--bt-l2cap cannot be combined with raw IPv4-only options\n");
      return 2;
    }
  }
  if (proto_mode != 0 && have_bt) {
    fprintf(stderr, "nfuzz: --proto and --bt-l2cap are mutually exclusive\n");
    return 2;
  }
  if (proto_reconnect && proto_mode != 1) {
    fprintf(stderr, "nfuzz: --proto-reconnect applies only to --proto tcp\n");
    return 2;
  }
  if (proto_connect_to < 1 || proto_connect_to > 300) {
    fprintf(stderr, "nfuzz: --proto-connect-timeout must be 1..300\n");
    return 2;
  }

  if (proto_mode != 0) {
    if (!dst_str || tpl_dport == 0) {
      fprintf(stderr, "nfuzz: --proto requires --dst and a non-zero --dport\n");
      return 2;
    }
    if (count < 1 || count > NFUZZ_MAX_COUNT) {
      fprintf(stderr, "nfuzz: count out of range\n");
      return 2;
    }
    if (rate > NFUZZ_MAX_RATE) {
      fprintf(stderr, "nfuzz: rate out of range\n");
      return 2;
    }
    struct in_addr dst_addr;
    if (parse_inaddr(dst_str, &dst_addr) != 0) {
      fprintf(stderr, "nfuzz: bad --dst\n");
      return 2;
    }
    unsigned char stream_tpl[NFUZZ_MAX_PACKET];
    int stlen = load_stream_base_payload(stream_tpl, NFUZZ_MAX_PACKET, hex_file,
        hex_arg, proto_payload_len, proto_payload_explicit);
    if (stlen < 0)
      return 2;
    if (stlen == 0) {
      stream_tpl[0] = 0;
      stlen = 1;
    }
    return run_proto_stream_fuzz(&dst_addr, tpl_dport, proto_mode == 1, stream_tpl,
        stlen, count, rate, strategy, mut_off, mut_len, seed_arg, proto_reconnect,
        proto_connect_to);
  }

#ifdef HAVE_BLUETOOTH_L2CAP
  if (have_bt) {
    if (count < 1 || count > NFUZZ_MAX_COUNT) {
      fprintf(stderr, "nfuzz: count out of range\n");
      return 2;
    }
    if (rate > NFUZZ_MAX_RATE) {
      fprintf(stderr, "nfuzz: rate out of range\n");
      return 2;
    }
    unsigned psm_use = bt_psm != 0 ? bt_psm : 4097u;
    unsigned char stream_tpl[NFUZZ_MAX_PACKET];
    int stlen = load_stream_base_payload(stream_tpl, NFUZZ_MAX_PACKET, hex_file,
        hex_arg, proto_payload_len, proto_payload_explicit);
    if (stlen < 0)
      return 2;
    if (stlen == 0) {
      stream_tpl[0] = 0;
      stlen = 1;
    }
    return run_bt_l2cap_fuzz(bt_l2cap_str, (uint16_t)psm_use, stream_tpl, stlen,
        count, rate, strategy, mut_off, mut_len, seed_arg);
  }
#endif

  if (!dst_str) {
    fprintf(stderr, "nfuzz: --dst ADDR is required (raw mode)\n");
    return 2;
  }

  struct in_addr dst_addr;
  if (parse_inaddr(dst_str, &dst_addr) != 0) {
    fprintf(stderr, "nfuzz: bad --dst\n");
    return 2;
  }

  struct in_addr src_patch;
  int have_src = 0;
  if (src_str) {
    if (parse_inaddr(src_str, &src_patch) != 0) {
      fprintf(stderr, "nfuzz: bad --src\n");
      return 2;
    }
    have_src = 1;
  }

  if (tpl_icmp_id > 65535u || tpl_icmp_seq > 65535u) {
    fprintf(stderr, "nfuzz: --icmp-id and --icmp-seq must be 0..65535\n");
    return 2;
  }
  if (tpl_payload_len > NFUZZ_MAX_PACKET - 80) {
    fprintf(stderr, "nfuzz: --payload-len too large\n");
    return 2;
  }
  if (frag_mtu > 0 && frag_mtu < 28) {
    fprintf(stderr, "nfuzz: --frag-mtu must be 0 (off) or at least 28\n");
    return 2;
  }
  if (pcap_index < 1) {
    fprintf(stderr, "nfuzz: --pcap-index must be >= 1\n");
    return 2;
  }
  if (tcp_mss > 65535u) {
    fprintf(stderr, "nfuzz: --tcp-mss out of range\n");
    return 2;
  }
  if ((ip_opt_hex != NULL || tcp_opt_hex != NULL || tcp_mss > 0)
      && template_name == NULL) {
    fprintf(stderr,
        "nfuzz: --ip-options-hex, --tcp-options-hex, and --tcp-mss require "
        "--template\n");
    return 2;
  }
  if ((tcp_opt_hex != NULL || tcp_mss > 0) && template_name != NULL
      && strcasecmp(template_name, "tcp-syn") != 0) {
    fprintf(stderr,
        "nfuzz: --tcp-options-hex and --tcp-mss apply only to --template tcp-syn\n");
    return 2;
  }

  uint32_t rng = (uint32_t)(seed_arg >= 0 ? seed_arg : (long)time(NULL) ^ (long)now_ns());
  if (rng == 0)
    rng = 0xdeadbeefu;

  unsigned char ip_opt_buf[44];
  unsigned ip_opt_n = 0;
  unsigned char tcp_opt_buf[44];
  unsigned tcp_opt_n = 0;

  if (ip_opt_hex != NULL) {
    int n = decode_hex_buffer(ip_opt_hex, strlen(ip_opt_hex), ip_opt_buf,
        sizeof(ip_opt_buf));
    if (n < 0) {
      fprintf(stderr, "nfuzz: invalid --ip-options-hex\n");
      return 2;
    }
    ip_opt_n = (unsigned)n;
    while (ip_opt_n < sizeof(ip_opt_buf) && (ip_opt_n % 4u) != 0)
      ip_opt_buf[ip_opt_n++] = 1; /* IP NOP */
    if (ip_opt_n > 40u) {
      fprintf(stderr, "nfuzz: --ip-options-hex too long after padding (max 40)\n");
      return 2;
    }
  }

  if (tcp_mss > 0) {
    if (tcp_opt_n + 4u > sizeof(tcp_opt_buf)) {
      fprintf(stderr, "nfuzz: TCP options overflow\n");
      return 2;
    }
    tcp_opt_buf[tcp_opt_n++] = 2;
    tcp_opt_buf[tcp_opt_n++] = 4;
    tcp_opt_buf[tcp_opt_n++] = (unsigned char)((tcp_mss >> 8) & 0xff);
    tcp_opt_buf[tcp_opt_n++] = (unsigned char)(tcp_mss & 0xff);
  }
  if (tcp_opt_hex != NULL) {
    int n = decode_hex_buffer(tcp_opt_hex, strlen(tcp_opt_hex),
        tcp_opt_buf + tcp_opt_n, sizeof(tcp_opt_buf) - tcp_opt_n);
    if (n < 0) {
      fprintf(stderr, "nfuzz: invalid --tcp-options-hex\n");
      return 2;
    }
    tcp_opt_n += (unsigned)n;
    while (tcp_opt_n < sizeof(tcp_opt_buf) && (tcp_opt_n % 4u) != 0)
      tcp_opt_buf[tcp_opt_n++] = 1; /* TCP NOP */
    if (tcp_opt_n > 40u) {
      fprintf(stderr, "nfuzz: --tcp-options-hex too long after padding (max 40)\n");
      return 2;
    }
  }

  unsigned char template[NFUZZ_MAX_PACKET];
  int tlen = 0;
  int from_template = 0;

  if (template_name) {
    if (hex_file != NULL || hex_arg != NULL || pcap_file != NULL) {
      fprintf(stderr,
          "nfuzz: --template is mutually exclusive with --hex, --hex-file, and "
          "--pcap\n");
      return 2;
    }
    from_template = 1;
    tlen = build_ipv4_template(template, NFUZZ_MAX_PACKET, template_name, dst_addr,
        have_src ? &src_patch : NULL, have_src, tpl_sport, tpl_dport,
        tpl_payload_len, (uint16_t)tpl_icmp_id, (uint16_t)tpl_icmp_seq, tpl_tcp_win,
        ip_opt_n > 0 ? ip_opt_buf : NULL, ip_opt_n,
        tcp_opt_n > 0 ? tcp_opt_buf : NULL, tcp_opt_n, &rng);
    if (tlen < 0) {
      fprintf(stderr,
          "nfuzz: unknown or invalid --template (try icmp-echo, udp, tcp-syn)\n");
      return 2;
    }
  } else if (pcap_file != NULL) {
    if (hex_file != NULL || hex_arg != NULL) {
      fprintf(stderr,
          "nfuzz: --pcap is mutually exclusive with --hex and --hex-file\n");
      return 2;
    }
    tlen = nfuzz_pcap_load_ipv4(pcap_file, pcap_index, template, NFUZZ_MAX_PACKET);
    if (tlen < 0)
      return 2;
  } else if (hex_file) {
    tlen = read_hex_file(hex_file, template, NFUZZ_MAX_PACKET);
    if (tlen < 0)
      return 2;
  } else if (hex_arg) {
    tlen = decode_hex_buffer(hex_arg, strlen(hex_arg), template, NFUZZ_MAX_PACKET);
    if (tlen < 0) {
      fprintf(stderr, "nfuzz: invalid --hex\n");
      return 2;
    }
  } else {
    fprintf(stderr,
        "nfuzz: provide --template, --pcap, --hex-file, or --hex (raw mode)\n");
    return 2;
  }

  if (tlen < 20) {
    fprintf(stderr, "nfuzz: packet too short for IPv4 (need at least 20 bytes)\n");
    return 2;
  }

  if ((template[0] >> 4) != 4) {
    fprintf(stderr, "nfuzz: base packet must be IPv4 (version nibble 4)\n");
    return 2;
  }

  if (count < 1 || count > NFUZZ_MAX_COUNT) {
    fprintf(stderr, "nfuzz: count out of range\n");
    return 2;
  }
  if (rate > NFUZZ_MAX_RATE) {
    fprintf(stderr, "nfuzz: rate out of range\n");
    return 2;
  }

  int fd = open_raw_socket();
  if (fd < 0) {
    fprintf(stderr, "nfuzz: raw socket failed: %s (need privileges?)\n",
        strerror(errno));
    return 1;
  }

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr = dst_addr;

  unsigned char work[NFUZZ_MAX_PACKET];
  unsigned long interval_ns = rate > 0 ? 1000000000UL / rate : 0;

  for (unsigned long n = 0; n < count; n++) {
    memcpy(work, template, (size_t)tlen);
    int len = tlen;

    if (patch_addresses) {
      if (have_src)
        memcpy(work + 12, &src_patch.s_addr, 4);
      memcpy(work + 16, &dst_addr.s_addr, 4);
    }

    unsigned ihl = ip_header_len(work, len);
    int moff;
    if (mut_off >= 0)
      moff = (int)mut_off;
    else if (from_template) {
      int po = nfuzz_payload_offset(work, len);
      if (po < 0) {
        fprintf(stderr, "nfuzz: cannot derive mutable region for template\n");
        close(fd);
        return 2;
      }
      moff = po;
    } else
      moff = (int)ihl;
    int mlen;
    if (mut_len >= 0)
      mlen = (int)mut_len;
    else
      mlen = len - moff;
    if (moff < 0 || moff > len || mlen < 0 || moff + mlen > len) {
      fprintf(stderr, "nfuzz: invalid mutable region\n");
      close(fd);
      return 2;
    }

    if (strcasecmp(strategy, "bitflip") == 0)
      mutate_bitflip(work, moff, mlen, &rng);
    else if (strcasecmp(strategy, "random_byte") == 0)
      mutate_random_byte(work, moff, mlen, &rng);
    else if (strcasecmp(strategy, "inc_byte") == 0)
      mutate_inc_byte(work, moff, mlen, &rng);
    else if (strcasecmp(strategy, "dec_byte") == 0)
      mutate_dec_byte(work, moff, mlen, &rng);
    else if (strcasecmp(strategy, "truncate") == 0)
      len = mutate_truncate(work, len, moff, mlen, &rng);
    else if (strcasecmp(strategy, "append_random") == 0)
      len = mutate_append(work, len, &rng);
    else if (strcasecmp(strategy, "shuffle_block") == 0)
      mutate_shuffle_block(work, moff, mlen, &rng);
    else {
      fprintf(stderr, "nfuzz: unknown strategy %s\n", strategy);
      close(fd);
      return 2;
    }

    if (len < 20) {
      fprintf(stderr, "nfuzz: packet length after mutation < 20, aborting\n");
      close(fd);
      return 1;
    }

    if (fix_ip_len)
      fix_ip_total_len(work, len);
    if (fix_csum)
      fix_ipv4_hdr_checksum(work, len);
    if (fix_l4)
      fix_udp_tcp_checksum(work, len);

    if (ipv4_send_with_frag_mtu(fd, work, len, &sin, frag_mtu, &rng) != 0) {
      close(fd);
      return 1;
    }

    if (rate > 0 && interval_ns > 0) {
      struct timespec sl;
      sl.tv_sec = (time_t)(interval_ns / 1000000000UL);
      sl.tv_nsec = (long)(interval_ns % 1000000000UL);
      nanosleep(&sl, NULL);
    }
  }

  close(fd);
  fprintf(stderr, "nfuzz: sent %lu packet(s)\n", count);
  return 0;
}
