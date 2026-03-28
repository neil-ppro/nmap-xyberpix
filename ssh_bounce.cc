/***************************************************************************
 * ssh_bounce.cc -- Start OpenSSH -D and set o.proxy_chain to SOCKS4        *
 *                  (nmap-ppro)                                             *
 ***************************************************************************/

#if HAVE_CONFIG_H
#include "nmap_config.h"
#else
#ifdef WIN32
#include "nmap_winconfig.h"
#endif
#endif

#include "nmap.h"
#include "NmapOps.h"
#include "nmap_error.h"
#include "nsock.h"
#include "ssh_bounce.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#if !defined(WIN32) && !defined(__amigaos__)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

extern NmapOps o;

#if !defined(WIN32) && !defined(__amigaos__)

static pid_t ssh_bounce_pid = 0;

void ssh_bounce_cleanup(void) {
  if (ssh_bounce_pid <= 0)
    return;
  kill(ssh_bounce_pid, SIGTERM);
  waitpid(ssh_bounce_pid, NULL, 0);
  ssh_bounce_pid = 0;
}

static int local_tcp_connect_ok(unsigned short port) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a;

  if (s < 0)
    return 0;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
    close(s);
    return 0;
  }
  close(s);
  return 1;
}

void ssh_bounce_start_if_needed(void) {
  static int atexit_registered = 0;

  if (o.ssh_bounce == NULL)
    return;
  if (o.ssh_bounce[0] == '\0')
    fatal("Empty --ssh-bounce target.");
  if (o.proxy_chain)
    fatal("--ssh-bounce cannot be used together with --proxies.");

  if (!atexit_registered) {
    atexit(ssh_bounce_cleanup);
    atexit_registered = 1;
  }

  const int max_attempts = 40;
  int attempt;

  for (attempt = 0; attempt < max_attempts; attempt++) {
    unsigned short port = (unsigned short)(40000 + (get_random_uint() % 20000));
    pid_t pid = fork();

    if (pid < 0)
      fatal("ssh-bounce: fork failed: %s", strerror(errno));

    if (pid == 0) {
      char dspec[64];
      char pspec[16];
      char *argv[20];
      int ac = 0;

      Snprintf(dspec, sizeof(dspec), "127.0.0.1:%u", (unsigned)port);
      argv[ac++] = const_cast<char *>("ssh");
      argv[ac++] = const_cast<char *>("-N");
      argv[ac++] = const_cast<char *>("-oExitOnForwardFailure=yes");
      argv[ac++] = const_cast<char *>("-oServerAliveInterval=60");
      argv[ac++] = const_cast<char *>("-D");
      argv[ac++] = dspec;
      if (o.ssh_bounce_remote_port != 22) {
        Snprintf(pspec, sizeof(pspec), "%u", (unsigned)o.ssh_bounce_remote_port);
        argv[ac++] = const_cast<char *>("-p");
        argv[ac++] = pspec;
      }
      argv[ac++] = const_cast<char *>("--");
      argv[ac++] = o.ssh_bounce;
      argv[ac] = NULL;
      execvp("ssh", argv);
      _exit(126);
    }

    struct timeval t0, now;

    gettimeofday(&t0, NULL);
    for (;;) {
      int st = 0;
      pid_t w = waitpid(pid, &st, WNOHANG);

      if (w == pid)
        break;
      if (local_tcp_connect_ok(port)) {
        char url[96];

        Snprintf(url, sizeof(url), "socks4://127.0.0.1:%u", (unsigned)port);
        if (nsock_proxychain_new(url, &o.proxy_chain, NULL) < 0)
          fatal("ssh-bounce: could not create proxy chain.");
        ssh_bounce_pid = pid;
        if (o.verbose)
          log_write(LOG_STDOUT,
              "ssh-bounce: SOCKS4 forward on 127.0.0.1:%u via ssh to %s\n",
              (unsigned)port, o.ssh_bounce);
        return;
      }
      gettimeofday(&now, NULL);
      if (TIMEVAL_MSEC_SUBTRACT(now, t0) > 25000)
        break;
      usleep(100000);
    }

    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
  }

  fatal("ssh-bounce: could not start SSH dynamic forward to %s (need OpenSSH "
        "client in PATH, working auth, and permission for -D).",
        o.ssh_bounce);
}

#else /* WIN32 || __amigaos__ */

void ssh_bounce_cleanup(void) {}

void ssh_bounce_start_if_needed(void) {
  if (o.ssh_bounce == NULL)
    return;
  fatal("--ssh-bounce is not available on this platform. Start a tunnel with "
        "your SSH client (e.g. \"ssh -N -D 1080 user@jump\") and pass "
        "--proxies socks4://127.0.0.1:1080.");
}

#endif
