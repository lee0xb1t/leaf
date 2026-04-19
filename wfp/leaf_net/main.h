#pragma once
#ifndef __MAIN_H
#define __MAIN_H

#include "driver.h"

VOID DriverUnload(WDFDRIVER WdfDriver);

NTSTATUS InitWdfObjects(
	IN PDRIVER_OBJECT DrvObj,
	IN PUNICODE_STRING RegistryPath,
	OUT WDFDRIVER* OutWdfDriver,
	OUT WDFDEVICE* OutWdfDevice);


VOID
IoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
);

#endif
