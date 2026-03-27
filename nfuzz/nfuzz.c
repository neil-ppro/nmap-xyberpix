/*
 * nfuzz — raw IPv4 packet mutation harness + optional HTTP fuzz server (nmap-ppro)
 *
 * Raw mode: sends crafted IPv4 datagrams via a raw socket (IP_HDRINCL).
 * HTTP mode: serves dynamically generated HTML/JS for authorized browser
 * (DOM/JS engine) fuzzing on a local or explicitly allowed bind address.
 *
 * Requires explicit --authorized (or NFUZZ_AUTHORIZED=1).
 *
 * Nmap and nfuzz are (C) Nmap Software LLC — see LICENSE in the distribution.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

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
  FILE *f = fopen(path, "w");
  if (!f) {
    fprintf(stderr, "nfuzz: cannot write pid file %s: %s\n", path,
        strerror(errno));
    return -1;
  }
  fprintf(f, "%ld\n", (long)getpid());
  fclose(f);
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

static int run_http_daemon(const char *bind_spec, size_t max_body,
    unsigned refresh_sec, int do_detach, const char *pid_file,
    int allow_remote, long seed_arg)
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

  for (;;) {
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
      req[total] = '\0';
      if (strstr(req, "\r\n\r\n") != NULL)
        break;
    }

    size_t blen = 0;
    if (build_http_fuzz_page(body, max_body, &blen, &rng, refresh_sec) != 0
        || blen == 0) {
      const char *err =
          "HTTP/1.1 500 Internal Server Error\r\n"
          "Connection: close\r\n"
          "Content-Length: 0\r\n\r\n";
      (void)send(c, err, strlen(err), 0);
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
      close(c);
      continue;
    }

    (void)send(c, hdr, hpos, 0);
    (void)send(c, body, blen, 0);
    close(c);
  }

  free(body);
  close(ls);
  return 0;
}

static void usage(FILE *fp, const char *argv0)
{
  fprintf(fp,
"Usage: %s --authorized { --http-daemon [http-options] | raw-packet-options }\n"
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
"\n"
"Raw IPv4 mode:\n"
"Target / addressing:\n"
"  --dst ADDR                Destination IPv4 (also used for sendto).\n"
"  --src ADDR                Patch IPv4 header source field (optional).\n"
"  --patch-addresses         Apply --src/--dst to bytes 12-19 of the IP header.\n"
"\n"
"Payload:\n"
"  --hex-file PATH           Base datagram as hex (whitespace ignored).\n"
"  --hex STRING              Base datagram as hex string.\n"
"\n"
"Fuzzing:\n"
"  -c, --count N             Packets to send (default 1, max %lu).\n"
"  -r, --rate RATE           Max packets/sec (0 = no limit, max %u).\n"
"  -s, --seed N              RNG seed (default: time).\n"
"  -S, --strategy NAME       bitflip | random_byte | inc_byte | dec_byte |\n"
"                            truncate | append_random | shuffle_block (default: bitflip).\n"
"  -m, --mutable-off O       Start of mutable region (byte offset, default: after IP hdr).\n"
"  -l, --mutable-len L       Length of mutable region (default: through end of buffer).\n"
"\n"
"Checksums / lengths:\n"
"  --fix-ip-len              Set IPv4 total length field from buffer length (default on).\n"
"  --no-fix-ip-len\n"
"  --fix-checksums           Recompute IPv4 header checksum (default on).\n"
"  --no-fix-checksums\n"
"  --fix-l4                  Recompute UDP (17) or TCP (6) checksum if present.\n"
"\n"
"Misc:\n"
"  -h, --help                This help.\n"
"  -V, --version             Version string.\n"
"\n"
"Environment:\n"
"  NFUZZ_AUTHORIZED=1        Same acknowledgement as --authorized (either is enough).\n"
"\n",
          argv0, NFUZZ_HTTP_DEFAULT_BIND,
          (unsigned)NFUZZ_HTTP_DEFAULT_MAX_BODY,
          NFUZZ_HTTP_DEFAULT_REFRESH, (unsigned long)NFUZZ_MAX_COUNT,
          NFUZZ_MAX_RATE);
}

static const char *version_string(void)
{
  return "nfuzz (nmap-ppro) 0.2";
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
  FILE *f = fopen(path, "rb");
  if (!f) {
    fprintf(stderr, "nfuzz: cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }
  char *buf = NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    fprintf(stderr, "nfuzz: fseek failed on %s\n", path);
    return -1;
  }
  long sz = ftell(f);
  if (sz < 0 || sz > NFUZZ_MAX_PACKET * 4) {
    fclose(f);
    fprintf(stderr, "nfuzz: file too large or unreadable: %s\n", path);
    return -1;
  }
  rewind(f);
  buf = (char *)malloc((size_t)sz + 1);
  if (!buf) {
    fclose(f);
    return -1;
  }
  size_t r = fread(buf, 1, (size_t)sz, f);
  fclose(f);
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

  if (http_daemon) {
    return run_http_daemon(http_bind, http_max_body, http_refresh, do_detach,
        pid_file, http_allow_remote, seed_arg);
  }

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

  unsigned char template[NFUZZ_MAX_PACKET];
  int tlen = 0;
  if (hex_file) {
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
    fprintf(stderr, "nfuzz: provide --hex-file or --hex\n");
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

  uint32_t rng = (uint32_t)(seed_arg >= 0 ? seed_arg : (long)time(NULL) ^ (long)now_ns());
  if (rng == 0)
    rng = 0xdeadbeefu;

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
    int moff = (mut_off >= 0) ? (int)mut_off : (int)ihl;
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

    ssize_t sent = sendto(fd, work, (size_t)len, 0,
        (struct sockaddr *)&sin, sizeof(sin));
    if (sent < 0) {
      fprintf(stderr, "nfuzz: sendto: %s\n", strerror(errno));
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
