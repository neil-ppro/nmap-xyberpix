/* macOS: L2CAP via IOBluetooth (see bt_l2cap_mac.m). C linkage for nfuzz.c. */
#ifndef NFUZZ_BT_L2CAP_MAC_H
#define NFUZZ_BT_L2CAP_MAC_H

#include <stdint.h>

/* 0 = success. -1 = bad address string. -2 = connect / channel open failed. */
int nfuzz_bt_mac_open(const char *addr_str, uint16_t psm_host, void **opaque);

/* 0 = success, -1 = write error */
int nfuzz_bt_mac_send(void *opaque, const unsigned char *data, int len);

void nfuzz_bt_mac_close(void *opaque);

#endif
