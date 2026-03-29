/***************************************************************************
 * siem_log.cc -- NDJSON SIEM-oriented scan events + optional RFC 5424       *
 ***************************************************************************/

#include "siem_log.h"
#include "nmap.h"
#include "Target.h"
#include "nbase.h"
#include "nmap_error.h"

#include <ctime>
#include <cstdio>
#include <cstring>
#include <string>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <vector>
#else
#include <sys/time.h>
#include <unistd.h>
#if !defined(__amigaos__)
#include <syslog.h>
#endif
#endif

#define SIEM_HOSTNAME_LEN 256
#define SIEM_SCHEMA_VERSION 1
/* Cap command line in scan_start JSON (join_quoted can be huge); UTF-8 safe prefix. */
#define SIEM_MAX_ARGS_UTF8_BYTES 131072

static FILE *siem_fp;
#ifndef WIN32
static FILE *siem_logger_pipe;
#if !defined(__amigaos__)
static bool siem_syslog_fallback; /* openlog/syslog when logger(1) unavailable */
#endif
#else
static HANDLE siem_win_event_source;
#endif
static char *siem_tag;
static char siem_scan_id[64];
static char siem_scanner_host[SIEM_HOSTNAME_LEN];

/* Truncate s to at most max_bytes UTF-8 without splitting a multibyte character. */
static std::string siem_utf8_prefix(const char *s, size_t max_bytes) {
  std::string out;
  if (!s || max_bytes == 0)
    return out;
  size_t n = strlen(s);
  if (n <= max_bytes) {
    out.assign(s, n);
    return out;
  }
  out.assign(s, max_bytes);
  while (!out.empty() && ((unsigned char)out.back() & 0xc0) == 0x80)
    out.pop_back();
  return out;
}

static std::string json_escape(const char *s) {
  std::string out;
  size_t slen;

  if (!s)
    return out;
  slen = strlen(s);
  out.reserve(slen + (slen >> 4) + 8);
  for (; *s; s++) {
    unsigned char c = (unsigned char) *s;
    switch (c) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\b':
      out += "\\b";
      break;
    case '\f':
      out += "\\f";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (c < 0x20) {
        char buf[8];
        Snprintf(buf, sizeof(buf), "\\u%04x", c);
        out += buf;
      } else {
        out += (char) c;
      }
    }
  }
  return out;
}

/* UTC ISO-8601 with millisecond (Windows) or microsecond (Unix) fractional part. */
static void siem_iso_timestamp_utc(char *buf, size_t buflen) {
#ifdef WIN32
  SYSTEMTIME st;

  GetSystemTime(&st);
  Snprintf(buf, buflen, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
           (unsigned) st.wYear, (unsigned) st.wMonth, (unsigned) st.wDay,
           (unsigned) st.wHour, (unsigned) st.wMinute, (unsigned) st.wSecond,
           (unsigned) st.wMilliseconds);
#else
  struct timeval tv;
  struct tm tm;
  char datepart[32];
  char frac[24];

  memset(&tv, 0, sizeof(tv));
  gettimeofday(&tv, NULL);
  gmtime_r(&tv.tv_sec, &tm);
  strftime(datepart, sizeof(datepart), "%Y-%m-%dT%H:%M:%S", &tm);
  Snprintf(frac, sizeof(frac), ".%06ldZ", (long) tv.tv_usec);
  Snprintf(buf, buflen, "%s%s", datepart, frac);
#endif
}

/* Common JSON envelope: schema_version, ts, event, scan_id, scanner_hostname, optional tag. */
static void siem_json_open_envelope(std::string &line, const char *event_literal) {
  char ts[48];
  char ver[16];

  siem_iso_timestamp_utc(ts, sizeof(ts));
  Snprintf(ver, sizeof(ver), "%d", SIEM_SCHEMA_VERSION);
  line.reserve(384);
  line = "{\"schema_version\":";
  line += ver;
  line += ",\"ts\":\"";
  line += ts;
  line += "\",\"event\":\"";
  line += event_literal;
  line += "\",\"scan_id\":\"";
  line += json_escape(siem_scan_id);
  line += "\",\"scanner_hostname\":\"";
  line += json_escape(siem_scanner_host);
  line += "\"";
  if (siem_tag) {
    line += ",\"tag\":\"";
    line += json_escape(siem_tag);
    line += "\"";
  }
}

static void rfc5424_sanitize_app_field(char *s) {
  /* HOSTNAME / APP-NAME: printable ASCII, no SP */
  for (; *s; s++) {
    if (*s <= 32 || *s > 126)
      *s = '-';
  }
}

/* RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
 * PRI = facility(1=user)*8 + severity(6=informational) = 14 */
static std::string rfc5424_line(const std::string &utf8_msg) {
  char pidbuf[32];
  char hostcopy[SIEM_HOSTNAME_LEN];
  std::string line;

#ifdef WIN32
  SYSTEMTIME st;

  GetSystemTime(&st);
  char tsbase[64];
  Snprintf(tsbase, sizeof(tsbase), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
           (unsigned) st.wYear, (unsigned) st.wMonth, (unsigned) st.wDay,
           (unsigned) st.wHour, (unsigned) st.wMinute, (unsigned) st.wSecond,
           (unsigned) st.wMilliseconds);
  Snprintf(pidbuf, sizeof(pidbuf), "%ld", (long) _getpid());
#else
  struct timeval tv;
  struct tm tm;
  char tsbase[32];
  char frac[24];

  memset(&tv, 0, sizeof(tv));
  gettimeofday(&tv, NULL);
  gmtime_r(&tv.tv_sec, &tm);
  strftime(tsbase, sizeof(tsbase), "%Y-%m-%dT%H:%M:%S", &tm);
  Snprintf(frac, sizeof(frac), ".%06ldZ", (long) tv.tv_usec);
  Snprintf(pidbuf, sizeof(pidbuf), "%ld", (long) getpid());
#endif

  Strncpy(hostcopy, siem_scanner_host, sizeof(hostcopy));
  rfc5424_sanitize_app_field(hostcopy);

  line.reserve(utf8_msg.size() + 128);
  line = "<14>1 ";
#ifdef WIN32
  line += tsbase;
#else
  line += tsbase;
  line += frac;
#endif
  line += " ";
  line += hostcopy;
  line += " nmap ";
  line += pidbuf;
  line += " siem - ";
  line += utf8_msg;
  return line;
}

#ifndef WIN32
static FILE *siem_try_logger_pipe(void) {
  static const char *const cmds[] = {
    "logger -t nmap-siem",
    "/usr/bin/logger -t nmap-siem",
    "/bin/logger -t nmap-siem",
    "/usr/local/bin/logger -t nmap-siem",
  };
  size_t i;

  for (i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
    FILE *f = popen(cmds[i], "w");

    if (f)
      return f;
  }
  return NULL;
}
#endif

#ifdef WIN32
static void siem_win_report_rfc5424(const std::string &rfc_utf8) {
  int nw;

  if (!siem_win_event_source)
    return;
  nw = MultiByteToWideChar(CP_UTF8, 0, rfc_utf8.c_str(), -1, NULL, 0);
  if (nw <= 0)
    return;
  std::vector<wchar_t> wbuf((size_t) nw);
  MultiByteToWideChar(CP_UTF8, 0, rfc_utf8.c_str(), -1, wbuf.data(), nw);
  {
    const wchar_t *strings[] = { wbuf.data() };

    ReportEventW(siem_win_event_source, EVENTLOG_INFORMATION_TYPE, 0, 0x00001001,
                   NULL, 1, 0, (LPCWSTR *) strings, NULL);
  }
}
#endif

static void siem_write_line(const std::string &json) {
  if (!siem_log_active())
    return;

  if (siem_fp) {
    fwrite(json.c_str(), 1, json.length(), siem_fp);
    fputc('\n', siem_fp);
    fflush(siem_fp);
  }
#ifdef WIN32
  if (siem_win_event_source) {
    std::string rfc = rfc5424_line(json);

    siem_win_report_rfc5424(rfc);
  }
#else
  if (siem_logger_pipe
#if !defined(__amigaos__)
      || siem_syslog_fallback
#endif
      ) {
    std::string rfc = rfc5424_line(json);

    if (siem_logger_pipe) {
      fwrite(rfc.c_str(), 1, rfc.length(), siem_logger_pipe);
      fputc('\n', siem_logger_pipe);
      fflush(siem_logger_pipe);
    }
#if !defined(__amigaos__)
    else if (siem_syslog_fallback)
      syslog(LOG_INFO, "%s", rfc.c_str());
#endif
  }
#endif
}

static void siem_make_scan_id(void) {
  u8 r[8];

  get_random_bytes(r, sizeof(r));
  Snprintf(siem_scan_id, sizeof(siem_scan_id), "%lx-%02x%02x%02x%02x%02x%02x%02x%02x",
           (unsigned long) time(NULL), r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
}

void siem_log_init(const char *path, bool append, const char *tag_or_null,
                   bool enable_syslog_logger) {
#ifndef WIN32
  siem_logger_pipe = NULL;
#if !defined(__amigaos__)
  siem_syslog_fallback = false;
#endif
#else
  siem_win_event_source = NULL;
#endif

  siem_tag = NULL;
  if (tag_or_null && *tag_or_null)
    siem_tag = strdup(tag_or_null);

  siem_make_scan_id();
  memset(siem_scanner_host, 0, sizeof(siem_scanner_host));
  if (gethostname(siem_scanner_host, sizeof(siem_scanner_host) - 1) != 0)
    Strncpy(siem_scanner_host, "unknown", sizeof(siem_scanner_host));

  siem_fp = NULL;
  if (path && *path) {
    if (path[0] == '-' && path[1] == '\0')
      siem_fp = stdout;
    else if (append)
      siem_fp = fopen(path, "a");
    else
      siem_fp = fopen(path, "w");
    if (!siem_fp)
      error("Warning: Failed to open SIEM log file %s; SIEM file output disabled "
            "(scan continues). Use --siem-syslog or fix permissions/path.", path);
  }

  if (enable_syslog_logger) {
#ifdef WIN32
    siem_win_event_source = RegisterEventSourceW(NULL, L"Nmap");
    if (!siem_win_event_source)
      error("Warning: RegisterEventSource failed for --siem-syslog; Windows Event Log SIEM output disabled.");
#else
    siem_logger_pipe = siem_try_logger_pipe();
#if !defined(__amigaos__)
    if (!siem_logger_pipe) {
      openlog("nmap-siem", LOG_PID | LOG_NDELAY, LOG_USER);
      siem_syslog_fallback = true;
    }
#else
    if (!siem_logger_pipe)
      error("Warning: --siem-syslog requires logger(1); syslog fallback unavailable on this platform.");
#endif
#endif
  }
}

void siem_log_close(void) {
  if (siem_fp && siem_fp != stdout) {
    fclose(siem_fp);
    siem_fp = NULL;
  } else {
    siem_fp = NULL;
  }
#ifndef WIN32
  if (siem_logger_pipe) {
    pclose(siem_logger_pipe);
    siem_logger_pipe = NULL;
  }
#if !defined(__amigaos__)
  if (siem_syslog_fallback) {
    closelog();
    siem_syslog_fallback = false;
  }
#endif
#else
  if (siem_win_event_source) {
    DeregisterEventSource(siem_win_event_source);
    siem_win_event_source = NULL;
  }
#endif
  if (siem_tag) {
    free(siem_tag);
    siem_tag = NULL;
  }
}

bool siem_log_active(void) {
  return siem_fp != NULL
#ifndef WIN32
         || siem_logger_pipe != NULL
#if !defined(__amigaos__)
         || siem_syslog_fallback
#endif
#else
         || siem_win_event_source != NULL
#endif
      ;
}

static const char *siem_preflight_risk_str(const struct siem_scan_start_context *c) {
  if (!c)
    return "low";
  if (c->timing_level >= 5)
    return "high";
  if (c->timing_level >= 4 && c->nse_enabled && !c->safe_profile)
    return "high";
  if (c->timing_level >= 4 || c->nse_enabled || c->os_detection || c->service_version_scan)
    return "medium";
  if (c->ping_disabled_with_portscan)
    return "medium";
  return "low";
}

static void siem_scan_start_append_policy_and_preflight(std::string &line,
    const struct siem_scan_start_context *c) {
  char tbuf[16];

  line += ",\"scanner_policy\":{";
  if (c) {
    line += "\"safe_profile\":";
    line += c->safe_profile ? "true" : "false";
    line += ",\"adaptive_rate\":";
    line += c->adaptive_rate ? "true" : "false";
    line += ",\"ipv6_robust\":";
    line += c->ipv6_robust ? "true" : "false";
    line += ",\"auto_hostgroup\":";
    line += c->auto_hostgroup ? "true" : "false";
  } else {
    line += "\"safe_profile\":false,\"adaptive_rate\":false,\"ipv6_robust\":false,"
            "\"auto_hostgroup\":false";
  }
  line += "}";
  line += ",\"timing_template\":";
  if (c && c->timing_level >= 0 && c->timing_level <= 5) {
    Snprintf(tbuf, sizeof(tbuf), "%d", c->timing_level);
    line += tbuf;
  } else {
    line += "null";
  }
  line += ",\"preflight_risk\":\"";
  line += json_escape(siem_preflight_risk_str(c));
  line += "\"";
  line += ",\"preflight_notes\":[";
  if (c) {
    bool first = true;
    auto note = [&line, &first](const char *literal) {
      if (!first)
        line += ",";
      first = false;
      line += "\"";
      line += literal;
      line += "\"";
    };
    if (c->safe_profile)
      note("safe_profile");
    if (c->adaptive_rate)
      note("adaptive_rate");
    if (c->ipv6_robust)
      note("ipv6_robust");
    if (c->auto_hostgroup)
      note("auto_hostgroup");
    if (c->nse_enabled)
      note("nse_scripts");
    if (c->os_detection)
      note("os_detection");
    if (c->service_version_scan)
      note("service_version_detection");
    if (c->ping_disabled_with_portscan)
      note("ping_discovery_disabled");
    if (c->timing_level >= 4)
      note("aggressive_or_insane_timing");
    if (c->timing_level >= 5)
      note("insane_timing");
  }
  line += "]";
}

void siem_log_scan_start(const char *args_quoted,
                         const struct siem_scan_start_context *ctx_or_null) {
  if (!siem_log_active())
    return;

  std::string line;

  siem_json_open_envelope(line, "scan_start");
  line += ",\"nmap_version\":\"";
  line += json_escape(NMAP_VERSION);
  line += "\",\"platform\":\"";
  line += json_escape(NMAP_PLATFORM);
  line += "\",\"pid\":";
  char pidbuf[32];
#ifdef WIN32
  Snprintf(pidbuf, sizeof(pidbuf), "%ld", (long) _getpid());
#else
  Snprintf(pidbuf, sizeof(pidbuf), "%ld", (long) getpid());
#endif
  line += pidbuf;
  line += ",\"args\":";
  if (args_quoted && *args_quoted) {
    std::string prefix = siem_utf8_prefix(args_quoted, SIEM_MAX_ARGS_UTF8_BYTES);
    line += "\"";
    line += json_escape(prefix.c_str());
    line += "\"";
  } else {
    line += "null";
  }
  siem_scan_start_append_policy_and_preflight(line, ctx_or_null);
  line += "}";
  siem_write_line(line);
}

void siem_log_scan_end(unsigned int numhosts_scanned, unsigned int numhosts_up,
                       double elapsed_sec) {
  if (!siem_log_active())
    return;

  std::string line;
  char elapsed[64];

  Snprintf(elapsed, sizeof(elapsed), "%.3f", elapsed_sec);
  siem_json_open_envelope(line, "scan_end");
  line += ",\"hosts_scanned\":";
  char nbuf[32];
  Snprintf(nbuf, sizeof(nbuf), "%u", numhosts_scanned);
  line += nbuf;
  line += ",\"hosts_up\":";
  Snprintf(nbuf, sizeof(nbuf), "%u", numhosts_up);
  line += nbuf;
  line += ",\"elapsed_sec\":";
  line += elapsed;
  line += "}";
  siem_write_line(line);
}

void siem_log_host(const Target *target, const char *status) {
  if (!siem_log_active() || !target || !status)
    return;

  std::string line;

  siem_json_open_envelope(line, "host");
  line += ",\"target_ip\":\"";
  line += json_escape(target->targetipstr());
  line += "\",\"target_hostname\":\"";
  line += json_escape(target->HostName());
  line += "\",\"status\":\"";
  line += json_escape(status);
  line += "\"}";
  siem_write_line(line);
}

void siem_log_port(const Target *target, unsigned short portno,
                   const char *proto, const char *state,
                   const char *service, const char *version) {
  if (!siem_log_active() || !target || !proto || !state)
    return;

  std::string line;
  char portbuf[16];

  Snprintf(portbuf, sizeof(portbuf), "%hu", portno);
  siem_json_open_envelope(line, "port");
  line += ",\"target_ip\":\"";
  line += json_escape(target->targetipstr());
  line += "\",\"port\":";
  line += portbuf;
  line += ",\"protocol\":\"";
  line += json_escape(proto);
  line += "\",\"state\":\"";
  line += json_escape(state);
  line += "\",\"service\":";
  if (service && *service) {
    line += "\"";
    line += json_escape(service);
    line += "\"";
  } else {
    line += "null";
  }
  line += ",\"version\":";
  if (version && *version) {
    line += "\"";
    line += json_escape(version);
    line += "\"";
  } else {
    line += "null";
  }
  line += "}";
  siem_write_line(line);
}

void siem_log_os_summary(const Target *target, const char *overall_result,
                         const char *os_names_pipe_separated, double best_accuracy_or_neg_one) {
  if (!siem_log_active() || !target || !overall_result)
    return;

  std::string line;

  siem_json_open_envelope(line, "os_summary");
  line += ",\"target_ip\":\"";
  line += json_escape(target->targetipstr());
  line += "\",\"overall_result\":\"";
  line += json_escape(overall_result);
  line += "\",\"os_guesses\":\"";
  line += json_escape(os_names_pipe_separated ? os_names_pipe_separated : "");
  line += "\",\"best_accuracy\":";
  if (best_accuracy_or_neg_one >= 0.0) {
    char abuf[32];
    Snprintf(abuf, sizeof(abuf), "%.4f", best_accuracy_or_neg_one);
    line += abuf;
  } else {
    line += "null";
  }
  line += "}";
  siem_write_line(line);
}

void siem_log_service_summary(const Target *target,
                              const char *hostnames_csv, const char *ostypes_csv,
                              const char *devicetypes_csv, const char *cpes_csv) {
  if (!siem_log_active() || !target)
    return;

  std::string line;

  siem_json_open_envelope(line, "service_summary");
  line += ",\"target_ip\":\"";
  line += json_escape(target->targetipstr());
  line += "\",\"service_hostnames\":\"";
  line += json_escape(hostnames_csv ? hostnames_csv : "");
  line += "\",\"service_ostypes\":\"";
  line += json_escape(ostypes_csv ? ostypes_csv : "");
  line += "\",\"service_devicetypes\":\"";
  line += json_escape(devicetypes_csv ? devicetypes_csv : "");
  line += "\",\"service_cpes\":\"";
  line += json_escape(cpes_csv ? cpes_csv : "");
  line += "\"}";
  siem_write_line(line);
}
