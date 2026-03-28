/***************************************************************************
 * ssh_bounce.h -- Optional SSH jump-host dynamic forward for --proxies      *
 *                 (nmap-xyberpix)                                              *
 ***************************************************************************/

#ifndef SSH_BOUNCE_H
#define SSH_BOUNCE_H

void ssh_bounce_start_if_needed(void);
void ssh_bounce_cleanup(void);

#endif /* SSH_BOUNCE_H */
