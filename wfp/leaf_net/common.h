#pragma once
#ifndef __COMMON_H
#define __COMMON_H

#include "driver.h"

BOOL CommonIsIpv4LAN(UINT32 v4_addr);
BOOL CommonIsIpv6LAN(FWP_BYTE_ARRAY16* v6_addr);

USHORT CommonGetWfpAddressType(
    const FWPS_INCOMING_VALUES* inFixedValues,
    UINT32 layerId
);

BOOL CommonIsLAN(
    const FWPS_INCOMING_VALUES* inFixedValues,
    UINT32 layerId,
    const PVOID remoteAddr
);

#endif