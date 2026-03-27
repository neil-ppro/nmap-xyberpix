/***************************************************************************
 * siem_log.h -- Optional NDJSON logging for security analytics / SIEM      *
 *                                                                         *
 * Emits newline-delimited JSON suitable for Splunk, Elastic, etc.         *
 * Optional --siem-syslog sends the same JSON as RFC 5424 to the system log   *
 * (Unix: logger/syslog; Windows: Event Log) without a SIEM file.            *
 ***************************************************************************/

#ifndef SIEM_LOG_H
#define SIEM_LOG_H

class Target;

void siem_log_init(const char *path_or_null, bool append, const char *tag_or_null,
                   bool enable_syslog_logger);
void siem_log_close(void);
bool siem_log_active(void);

void siem_log_scan_start(const char *args_quoted);
void siem_log_scan_end(unsigned int numhosts_scanned, unsigned int numhosts_up,
                       double elapsed_sec);

void siem_log_host(const Target *target, const char *status);

void siem_log_port(const Target *target, unsigned short portno,
                   const char *proto, const char *state,
                   const char *service, const char *version);

void siem_log_os_summary(const Target *target, const char *overall_result,
                         const char *os_names_pipe_separated, double best_accuracy_or_neg_one);

void siem_log_service_summary(const Target *target,
                              const char *hostnames_csv, const char *ostypes_csv,
                              const char *devicetypes_csv, const char *cpes_csv);

#endif
