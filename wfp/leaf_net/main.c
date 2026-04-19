#include "driver.h"
#include "main.h"
#include "leafnet.h"
#include "devicecontrol.h"
#include "redirectctx.h"

#define LEAF_DEVICE_NAME		L"\\Device\\Leaf_NetFilter"
#define LEAF_SYM_NAME			L"\\??\\Leaf_NetFilter"

WDFQUEUE g_WdfQueue;


NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegistryPath) {
	NTSTATUS status = STATUS_SUCCESS;

	WDFDRIVER WdfDriver;
	WDFDEVICE WdfDevice;

	BOOLEAN IsLeafInit = FALSE;
	BOOL IsRedirectCtxInit = FALSE;
	
	status = InitWdfObjects(DrvObj, RegistryPath, &WdfDriver, &WdfDevice);
	if (!NT_SUCCESS(status)) {
		goto end0;
	}
	
	status = LeafNetInit(WdfDevice);
	if (!NT_SUCCESS(status)) {
		goto end0;
	}
	IsLeafInit = TRUE;

	status = RedirectCtxInit();
	if (!NT_SUCCESS(status)) {
		goto end0;
	}
	IsRedirectCtxInit = TRUE;

end0:
	if (!NT_SUCCESS(status)) {
		if (IsLeafInit) {
			LeafNetDestroy();
		}

		if (IsRedirectCtxInit) {
			RedirectCtxDestroy();
		}
	}
	return status;
}

VOID DriverUnload(WDFDRIVER WdfDriver) {
	UNREFERENCED_PARAMETER(WdfDriver);
	LeafNetDestroy();
}

NTSTATUS InitWdfObjects(
	IN PDRIVER_OBJECT DrvObj,
	IN PUNICODE_STRING RegistryPath,
	OUT WDFDRIVER* OutWdfDriver,
	OUT WDFDEVICE* OutWdfDevice)
{
	NTSTATUS status = STATUS_SUCCESS;

	WDFDRIVER WdfDriver;
	WDFDEVICE WdfDevice;

	WDF_DRIVER_CONFIG WdfDriverConf;

	PWDFDEVICE_INIT pWdfDeviceInit = NULL;

	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(LEAF_DEVICE_NAME);
	UNICODE_STRING SymName = RTL_CONSTANT_STRING(LEAF_SYM_NAME);

	WDF_IO_QUEUE_CONFIG IoQueueConfig;


	WDF_DRIVER_CONFIG_INIT(&WdfDriverConf, WDF_NO_EVENT_CALLBACK);
	WdfDriverConf.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	WdfDriverConf.EvtDriverUnload = DriverUnload;

	status = WdfDriverCreate(DrvObj,
		RegistryPath, 
		WDF_NO_OBJECT_ATTRIBUTES,
		&WdfDriverConf,
		&WdfDriver);

	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wdf drvier create failed, status = 0x%x\n", status));
		goto end0;
	}

	pWdfDeviceInit = WdfControlDeviceInitAllocate(WdfDriver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
	if (!pWdfDeviceInit) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto end0;
	}

	WdfDeviceInitSetDeviceType(pWdfDeviceInit, FILE_DEVICE_NETWORK);
	WdfDeviceInitSetCharacteristics(pWdfDeviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);

	status = WdfDeviceInitAssignName(pWdfDeviceInit, &DeviceName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wdf device assign name, status = 0x%x\n", status));
		goto end0;
	}

	WdfDeviceInitSetDeviceClass(pWdfDeviceInit, &GUID_DEVCLASS_NET);

	status = WdfDeviceCreate(&pWdfDeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &WdfDevice);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wdf device create failed, status = 0x%x\n", status));
		goto end0;
	}

	status = WdfDeviceCreateSymbolicLink(WdfDevice, &SymName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] symbolic link create failed, status: 0x%08X\n", status));
		goto end0;
	}


	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&IoQueueConfig, WdfIoQueueDispatchParallel);
	IoQueueConfig.EvtIoDeviceControl = IoDeviceControl;
    status = WdfIoQueueCreate(WdfDevice,
                              &IoQueueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &g_WdfQueue);
    if (!NT_SUCCESS(status)) {
        goto end0;
    }

	WdfControlFinishInitializing(WdfDevice);

	*OutWdfDriver = WdfDriver;
	*OutWdfDevice = WdfDevice;

end0:
	if (pWdfDeviceInit) WdfDeviceInitFree(pWdfDeviceInit);
	return status;
}

VOID
IoDeviceControl(
	_In_ WDFQUEUE Queue,
	_In_ WDFREQUEST Request,
	_In_ size_t OutputBufferLength,
	_In_ size_t InputBufferLength,
	_In_ ULONG IoControlCode
) {
	UNREFERENCED_PARAMETER(Queue);
	UNREFERENCED_PARAMETER(Request);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(IoControlCode);

	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR information = 0;

	HANDLE current_pid = (HANDLE)IoGetRequestorProcessId(WdfRequestWdmGetIrp(Request));;

	switch (IoControlCode) {
	case IOCTL_PROXY_TCP_INIT:
		status = RedirectCtxAddBypassPid(RC_PROTO_TYPE_TCP, current_pid);
		if (!NT_SUCCESS(status)) {
			goto end0;
		}
		RedirectCtxSetProxyType(RC_PROTO_TYPE_TCP, RC_PROXY_TYPE_INCLUDED);
		KdPrint(("Set process id: %p successful\n", current_pid));
		break;
	case IOCTL_PROXY_TCP_SET_INCLUDED:
		RedirectCtxSetProxyType(RC_PROTO_TYPE_TCP, RC_PROXY_TYPE_INCLUDED);
		break;
	case IOCTL_PROXY_TCP_SET_EXCLUDED:
		RedirectCtxSetProxyType(RC_PROTO_TYPE_TCP, RC_PROXY_TYPE_EXCLUDED);
		break;
	case IOCTL_PROXY_TCP_SET_PORT:
	{
		USHORT* Port = 0;
		size_t Length = 0;
		status = WdfRequestRetrieveInputBuffer(Request, sizeof(USHORT), &Port, &Length);
		if (!NT_SUCCESS(status)) {
			goto end0;
		}
		RedirectCtxSetProxyPort(RC_PROTO_TYPE_TCP, *Port);
		break;
	}
	case IOCTL_PROXY_TCP_ADD_PROCESS:
	{
		HANDLE* Pid = 0;
		size_t Length = 0;
		status = WdfRequestRetrieveInputBuffer(Request, sizeof(HANDLE), (PVOID*)&Pid, &Length);
		if (!NT_SUCCESS(status)) {
			goto end0;
		}
		status = RedirectCtxAddProxyPid(RC_PROTO_TYPE_TCP, *Pid);
		if (!NT_SUCCESS(status)) {
			goto end0;
		}
		break;
	}
	case IOCTL_PROXY_TCP_DESTROY:
	{
		status = RedirectCtxReInit(RC_PROTO_TYPE_TCP);
		if (!NT_SUCCESS(status)) {
			goto end0;
		}
		break;
	}
	default:
		break;
	}

end0:
	WdfRequestCompleteWithInformation(Request, status, information);
}