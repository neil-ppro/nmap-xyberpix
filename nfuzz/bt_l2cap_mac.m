/*
 * nfuzz — macOS Bluetooth L2CAP using IOBluetooth (nmap-xyberpix)
 *
 * Nmap and nfuzz are (C) Nmap Software LLC — see LICENSE in the distribution.
 */

#import <Foundation/Foundation.h>
#import <IOBluetooth/IOBluetooth.h>

#include "bt_l2cap_mac.h"

int nfuzz_bt_mac_open(const char *addr_str, uint16_t psm_host, void **opaque)
{
  if (!addr_str || !opaque)
    return -1;
  *opaque = NULL;

  @autoreleasepool {
    NSString *s = [NSString stringWithUTF8String:addr_str];
    if (!s)
      return -1;
    IOBluetoothDevice *dev = [IOBluetoothDevice deviceWithAddressString:s];
    if (dev == nil)
      return -1;

    IOBluetoothL2CAPChannel *ch = nil;
    IOReturn r = [dev openL2CAPChannelSync:&ch withPSM:psm_host delegate:nil];
    if (r != kIOReturnSuccess || ch == nil)
      return -2;

    [ch retain];
    *opaque = ch;
    return 0;
  }
}

int nfuzz_bt_mac_send(void *opaque, const unsigned char *data, int len)
{
  if (!opaque || !data || len < 0)
    return -1;
  IOBluetoothL2CAPChannel *ch = (IOBluetoothL2CAPChannel *)opaque;

  BluetoothL2CAPMTU mtu = [ch outgoingMTU];
  if (mtu < 1)
    mtu = 672;

  int off = 0;
  while (off < len) {
    int remain = len - off;
    UInt16 chunk = (UInt16)(remain > (int)mtu ? (int)mtu : remain);
    IOReturn r = [ch writeSync:(void *)(data + (size_t)off) length:chunk];
    if (r != kIOReturnSuccess)
      return -1;
    off += (int)chunk;
  }
  return 0;
}

void nfuzz_bt_mac_close(void *opaque)
{
  if (!opaque)
    return;
  IOBluetoothL2CAPChannel *ch = (IOBluetoothL2CAPChannel *)opaque;
  [ch closeChannel];
  [ch release];
}
