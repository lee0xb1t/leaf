#ifndef __DRIVER_H
#define __DRIVER_H

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>

#include <guiddef.h>
#include <initguid.h>
#include <devguid.h>

#pragma warning(push)
#pragma warning(disable: 4201)
#include <fwpsk.h>
#pragma warning(pop)

#include <fwpmk.h>
#include <ndis.h>

#include <sdkddkver.h>

// {2ED1C1D0-E19F-4BA5-B543-30B574116EAD}
DEFINE_GUID(LEAF_PROVIDER_ID,
	0x2ed1c1d0, 0xe19f, 0x4ba5, 0xb5, 0x43, 0x30, 0xb5, 0x74, 0x11, 0x6e, 0xad);


#endif