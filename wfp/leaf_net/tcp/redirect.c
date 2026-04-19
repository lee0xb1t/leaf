#include "redirect.h"
#include "../redirectctx.h"
#include "../common.h"
#include <mstcpip.h>

//
// Variables
//

HANDLE g_Redirecthandle = NULL;

PIO_WORKITEM g_RedirectWorkItem = NULL;


//
// Prototypes
//

// Ale Connect

NTSTATUS TcpRedirectpAleConnectCalloutInit(
	IN HANDLE WfpHandle,
	IN OUT PDEVICE_OBJECT DeviceObj,
	IN const GUID* SubLayerKey,
	IN ADDRESS_FAMILY AddressFamily,
	FWPS_CALLOUT_CLASSIFY_FN ClassifyFn,
	FWPS_CALLOUT_NOTIFY_FN NotifyFn
);

NTSTATUS TcpRedirectpAleConnectFilterInit(
	IN HANDLE WfpHandle,
	IN const GUID* SubLayerKey,
	IN const GUID* AleCCalloutKey,
	IN const GUID* LayerKey,
	IN PCWCHAR Name,
	IN PCWCHAR Description,
	IN const GUID* FilterKey
);

VOID TcpRedirectpAleConnectV4CalloutDestroy(
	IN HANDLE WfpHandle
);

VOID TcpRedirectpAleConnectV6CalloutDestroy(
	IN HANDLE WfpHandle
);

// Ale Connect Callbacks

VOID TcpRedirectpAleCClassify(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

NTSTATUS TcpRedirectpAleCNotify(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER3* filter
);


//
// Implements
//

NTSTATUS TcpRedirectInit(
	IN HANDLE WfpHandle,
	IN OUT WDFDEVICE WdfDevice,
	IN const GUID* ProviderKey,
	IN const GUID* SubLayerKey
)
{
	NTSTATUS status = STATUS_SUCCESS;

	BOOL IsV4Inited = FALSE;
	BOOL IsV6Inited = FALSE;
	BOOL IsRedirectHandleCreated = FALSE;
	BOOL IsWorkItemInited = FALSE;

	PDEVICE_OBJECT DeviceObj = WdfDeviceWdmGetDeviceObject(WdfDevice);

	g_RedirectWorkItem = IoAllocateWorkItem(DeviceObj);

	if (!g_RedirectWorkItem) {
		KdPrint(("[LeafNet] Tcp redirect workitem init failed, status = 0x%x\n", status));
		goto end0;
	}

	IsWorkItemInited = TRUE;


	status = FwpsRedirectHandleCreate(ProviderKey, 0, &g_Redirecthandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Tcp redirect handle create failed, status = 0x%x\n", status));
		goto end0;
	}

	IsRedirectHandleCreated = TRUE;

	//
	// V4
	//
	status = TcpRedirectpAleConnectCalloutInit(
		WfpHandle,
		DeviceObj,
		SubLayerKey,
		AF_INET,
		TcpRedirectpAleCClassify,
		TcpRedirectpAleCNotify
	);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Tcp v4 redirect callout init failed, status = 0x%x\n", status));
		goto end0;
	}

	IsV4Inited = TRUE;

	//
	// V6
	//
	
	status = TcpRedirectpAleConnectCalloutInit(
		WfpHandle,
		DeviceObj,
		SubLayerKey,
		AF_INET6,
		TcpRedirectpAleCClassify,
		TcpRedirectpAleCNotify
	);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Tcp v6 redirect callout v4 init failed, status = 0x%x\n", status));
		goto end0;
	}

	IsV6Inited = TRUE;

end0:
	if (!NT_SUCCESS(status)) {
		if (IsV4Inited) {
			TcpRedirectpAleConnectV4CalloutDestroy(WfpHandle);
		}
		if (IsV6Inited) {
			TcpRedirectpAleConnectV6CalloutDestroy(WfpHandle);
		}
		if (IsRedirectHandleCreated) {
			FwpsRedirectHandleDestroy(g_Redirecthandle);
		}

		if (IsWorkItemInited) {
			IoFreeWorkItem(g_RedirectWorkItem);
		}
	}

	return status;
}

VOID TcpRedirectDestroy(IN HANDLE WfpHandle) {
	TcpRedirectpAleConnectV4CalloutDestroy(WfpHandle);
	TcpRedirectpAleConnectV6CalloutDestroy(WfpHandle);

	if (g_RedirectWorkItem) {
		IoFreeWorkItem(g_RedirectWorkItem);
		g_RedirectWorkItem = NULL;
	}
}

NTSTATUS TcpRedirectpAleConnectCalloutInit(
	IN HANDLE WfpHandle,
	IN OUT PDEVICE_OBJECT DeviceObj,
	IN const GUID* SubLayerKey,
	IN ADDRESS_FAMILY AddressFamily,
	FWPS_CALLOUT_CLASSIFY_FN ClassifyFn,
	FWPS_CALLOUT_NOTIFY_FN NotifyFn
) {
	NTSTATUS status = STATUS_SUCCESS;

	FWPS_CALLOUT sCallout = { 0 };
	FWPM_CALLOUT mCallout = { 0 };

	FWPM_DISPLAY_DATA displayData = { 0 };

	const GUID* AleCCalloutKey = &TCP_REDIRECT_ALE_CONNECT_V4_CALLOUT;
	const GUID* LayerKey = &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
	const GUID* FilterKey = &TCP_REDIRECT_ALE_CONNECT_FILTER_V4;

	BOOL IsRuntimeCalloutCreated = FALSE;
	BOOL IsManagementCalloutCreated = FALSE;

	BOOL IsFilterInited = FALSE;

	NT_ASSERT(AddressFamily == AF_INET || AddressFamily == AF_INET6);

	if (AddressFamily == AF_INET6) {
		AleCCalloutKey = &TCP_REDIRECT_ALE_CONNECT_V6_CALLOUT;
		LayerKey = &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6;
		FilterKey = &TCP_REDIRECT_ALE_CONNECT_FILTER_V6;
	}

	// Callouts

	sCallout.calloutKey = *AleCCalloutKey;
	sCallout.classifyFn = ClassifyFn;
	sCallout.notifyFn = NotifyFn;

	status = FwpsCalloutRegister(DeviceObj, &sCallout, NULL);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Tcp %s redirect runtime callout add failed, status = 0x%x\n",
			(AddressFamily == AF_INET ? "v4" : "v6"),
			status));
		goto end0;
	}

	IsRuntimeCalloutCreated = TRUE;

	if (AddressFamily == AF_INET) {
		displayData.name = L"AlcConnectV4RedirectCallout";
		displayData.description = L"Redirect tcp v4 connections";
	} else {
		displayData.name = L"AlcConnectV6RedirectCallout";
		displayData.description = L"Redirect tcp v6 connections";
	}
	

	mCallout.calloutKey = *AleCCalloutKey;
	mCallout.applicableLayer = *LayerKey;
	mCallout.displayData = displayData;

	status = FwpmCalloutAdd(WfpHandle, &mCallout, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Tcp %s redirect management callout add failed, status = 0x%x\n", 
			(AddressFamily == AF_INET ? "v4" : "v6"),
			status));
		goto end0;
	}

	IsManagementCalloutCreated = TRUE;

	if (AddressFamily == AF_INET) {
		status = TcpRedirectpAleConnectFilterInit(
			WfpHandle,
			SubLayerKey,
			AleCCalloutKey,
			LayerKey,
			L"AlcConnectV4RedirectFilter",
			L"Redirect tcp v4 connections for filter",
			FilterKey
		);
	} else {
		status = TcpRedirectpAleConnectFilterInit(
			WfpHandle,
			SubLayerKey,
			AleCCalloutKey,
			LayerKey,
			L"AlcConnectV6RedirectFilter",
			L"Redirect tcp v6 connections for filter",
			FilterKey
		);
	}
	
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Tcp %s redirect filter init failed, status = 0x%x\n",
			(AddressFamily == AF_INET ? "v4" : "v6"),
			status));
		goto end0;
	}

	IsFilterInited = TRUE;

end0:
	if (!NT_SUCCESS(status)) {
		if (IsRuntimeCalloutCreated) {
			FwpsCalloutUnregisterByKey(AleCCalloutKey);
		}
		if (IsManagementCalloutCreated) {
			FwpmCalloutDeleteByKey(WfpHandle, AleCCalloutKey);
		}
		if (IsFilterInited) {
			FwpmFilterDeleteByKey(WfpHandle, FilterKey);
		}
	}

	return status;
}

VOID TcpRedirectpAleConnectV4CalloutDestroy(
	IN HANDLE WfpHandle
) {
	FwpmFilterDeleteByKey(WfpHandle, &TCP_REDIRECT_ALE_CONNECT_FILTER_V4);
	FwpsCalloutUnregisterByKey(&TCP_REDIRECT_ALE_CONNECT_V4_CALLOUT);
	FwpmCalloutDeleteByKey(WfpHandle, &TCP_REDIRECT_ALE_CONNECT_V4_CALLOUT);
}

VOID TcpRedirectpAleConnectV6CalloutDestroy(
	IN HANDLE WfpHandle
) {
	FwpmFilterDeleteByKey(WfpHandle, &TCP_REDIRECT_ALE_CONNECT_FILTER_V6);
	FwpsCalloutUnregisterByKey(&TCP_REDIRECT_ALE_CONNECT_V6_CALLOUT);
	FwpmCalloutDeleteByKey(WfpHandle, &TCP_REDIRECT_ALE_CONNECT_V6_CALLOUT);
}

NTSTATUS TcpRedirectpAleConnectFilterInit(
	IN HANDLE WfpHandle,
	IN const GUID* SubLayerKey,
	IN const GUID* AleCCalloutKey,
	IN const GUID* LayerKey,
	IN PCWCHAR Name,
	IN PCWCHAR Description,
	IN const GUID* FilterKey
) {
	NTSTATUS status = STATUS_SUCCESS;

	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION filterConditions[3] = { 0 };
	UINT conditionIndex = 0;

	filter.layerKey = *LayerKey;
	filter.displayData.name = (PWCHAR)Name;
	filter.displayData.description = (PWCHAR)Description;

	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = *AleCCalloutKey;
	filter.filterCondition = filterConditions;
	filter.subLayerKey = *SubLayerKey;
	filter.weight.type = FWP_EMPTY; // auto-weight
	//filter.rawContext = Context;
	filter.filterKey = *FilterKey;

	filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
	filterConditions[conditionIndex].matchType = FWP_MATCH_EQUAL;
	filterConditions[conditionIndex].conditionValue.type = FWP_UINT8;
	filterConditions[conditionIndex].conditionValue.uint8 = IPPROTO_TCP;
	conditionIndex++;

	filter.numFilterConditions = conditionIndex;

	status = FwpmFilterAdd(
		WfpHandle,
		&filter,
		NULL,
		NULL
	);

	return status;
}

//
// https://github.com/uri247/wdk81/blob/5a28cfcafb45fcc7fcbb5bb1975cddfd7202f98f/Windows%20Filtering%20Platform%20Sample/C%2B%2B/sys/ClassifyFunctions_ProxyCallouts.cpp#L1643
// https://learn.microsoft.com/zh-cn/windows-hardware/drivers/network/using-bind-or-connect-redirection
//

VOID TcpRedirectpAleCClassify(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
) 
{
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(layerData);

	NTSTATUS status = STATUS_SUCCESS;

	HANDLE process_id = NULL;
	BOOL is_bypass_process = FALSE;
	BOOL is_proxy_process = FALSE;
	RC_PROXY_TYPE proxy_type;
	BOOL is_proxy = FALSE;

	PVOID pRedirectContext = NULL;

	UINT64 ClassifyHandle = 0;
	BOOL IsCreateClassifyHandle = FALSE;
	PVOID WritableLayerData = NULL;
	FWPS_CONNECT_REQUEST* ConnectRequest = NULL;

	BOOL IsLAN = FALSE;

	ADDRESS_FAMILY addrf = (inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4) ? AF_INET : AF_INET6;

	if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
		goto end0;
	}

	if (!classifyContext) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto end0;
	}

	// TODO: ipv6
	if (addrf == AF_INET6) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto end0;
	}


#if (NTDDI_VERSION >= NTDDI_WIN8)
	FWPS_CONNECTION_REDIRECT_STATE redirectionState = FWPS_CONNECTION_NOT_REDIRECTED;

	if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)) {
		redirectionState = FwpsQueryConnectionRedirectState(inMetaValues->redirectRecords, g_Redirecthandle, &pRedirectContext);
	}

	switch (redirectionState)
	{
		/// Go ahead and continue with our redirection
		case FWPS_CONNECTION_NOT_REDIRECTED:
		case FWPS_CONNECTION_REDIRECTED_BY_OTHER:
		{
			break;
		}
		/// We've already seen this, so let it through
		case FWPS_CONNECTION_REDIRECTED_BY_SELF:
		{
			classifyOut->actionType = FWP_ACTION_PERMIT;
			goto end0;
		}
		/// Must not perform redirection. In this case we are letting the last redirection action win.
		case FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF:
		{
			goto end0;
		}
	}
#else
	// TODO WIN7
	NT_ASSERT(TRUE);
#endif

	if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
		process_id = (HANDLE)inMetaValues->processId;
	}

	if (!process_id) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto end0;
	}

	is_bypass_process = RedirectCtxIsBypassProcess(RC_PROTO_TYPE_TCP, process_id);
	if (is_bypass_process) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto end0;
	}

	proxy_type = RedirectCtxGetProxyType(RC_PROTO_TYPE_TCP);
	is_proxy_process = RedirectCtxIsProxyProcess(RC_PROTO_TYPE_TCP, process_id);
	if (is_bypass_process && proxy_type == RC_PROXY_TYPE_INCLUDED) {
		is_proxy = TRUE;
	} else if (!is_bypass_process && proxy_type == RC_PROXY_TYPE_EXCLUDED) {
		is_proxy = TRUE;
	}

	if (!is_proxy) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto end0;
	}


	if (addrf == AF_INET) {
		UINT32 ipv4_remote_addr = RtlUlongByteSwap(
			inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32
		);
		IsLAN = CommonIsIpv4LAN(ipv4_remote_addr);
	}
	else {
		// TODO: ipv6
		IsLAN = TRUE;
	}

	if (IsLAN) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto end0;
	}

	/*
	RedirectData = ExAllocatePool3(POOL_FLAG_NON_PAGED, sizeof(REDIRECT_DATA), 'tcdR', NULL, 0);
	if (!RedirectData) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto end0;
	}

	RedirectData->process_id = process_id;

	if (addrf == AF_INET) {
		RedirectData->ipv4_remote_addr =  RtlUlongByteSwap(
				inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32
			);
	} else {
		// TODO: ipv6
	}
	RedirectData->remote_port = RtlUshortByteSwap(
			inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16
		);
	RedirectData->local_port = RtlUshortByteSwap(
		inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT].value.uint16
	);
	*/

	status = FwpsAcquireClassifyHandle((PVOID)classifyContext, 0, &ClassifyHandle);
	if (!NT_SUCCESS(status)) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto end0;
	}

	IsCreateClassifyHandle = TRUE;

	status = FwpsAcquireWritableLayerDataPointer(
		ClassifyHandle,
		filter->filterId,
		0,
		&WritableLayerData,
		classifyOut
	);
	if (!NT_SUCCESS(status)) {
		goto end0;
	}
	
	ConnectRequest = (FWPS_CONNECT_REQUEST*)WritableLayerData;

#if (NTDDI_VERSION >= NTDDI_WIN8)
	ConnectRequest->localRedirectHandle = g_Redirecthandle;
#endif

#pragma warning(push)
#pragma warning(disable: 4311)
	ConnectRequest->localRedirectTargetPID = (DWORD)RedirectCtxGetFirstBypassPid(RC_PROTO_TYPE_TCP);
#pragma warning(pop)
	

	if (INETADDR_ISANY((PSOCKADDR)&(ConnectRequest->localAddressAndPort))) {
		INETADDR_SETLOOPBACK((PSOCKADDR)&(ConnectRequest->remoteAddressAndPort));
	} else {
		INETADDR_SET_ADDRESS((PSOCKADDR) & (ConnectRequest->remoteAddressAndPort),
			INETADDR_ADDRESS((PSOCKADDR) & (ConnectRequest->localAddressAndPort)));
	}

	USHORT port = RtlUshortByteSwap(RedirectCtxGetProxyPort(RC_PROTO_TYPE_TCP));
	INETADDR_SET_PORT((PSOCKADDR)&(ConnectRequest->remoteAddressAndPort), port);



	//---------------------------------------------
	REDIRECT_DATA* redirectContext =
		(REDIRECT_DATA*)ExAllocatePoolWithTag(
			NonPagedPoolNx,
			sizeof(REDIRECT_DATA),
			'LRdC'
		);

	if (redirectContext) {
		RtlZeroMemory(redirectContext, sizeof(REDIRECT_DATA));

		if (addrf == AF_INET) {
			SOCKADDR_IN* peerAddr = (SOCKADDR_IN*)&redirectContext->peerAddress;
			peerAddr->sin_family = AF_INET;
			peerAddr->sin_port = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;
			peerAddr->sin_addr.S_un.S_addr = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
		}
		// TODO: Ìí¼Ó IPv6 Ö§³Ö

		SOCKADDR_IN* originAddr = (SOCKADDR_IN*)&redirectContext->originAddress;
		originAddr->sin_family = AF_INET;
		originAddr->sin_port = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT].value.uint16;
		originAddr->sin_addr.S_un.S_addr = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS].value.uint32;

		ConnectRequest->localRedirectContext = redirectContext;
		ConnectRequest->localRedirectContextSize = sizeof(REDIRECT_DATA);
	}
	//---------------------------------------------




	FwpsApplyModifiedLayerData(
		ClassifyHandle,
		WritableLayerData,
		0
	);


	FwpsReleaseClassifyHandle(ClassifyHandle);

	classifyOut->actionType = FWP_ACTION_PERMIT;
	classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

	SOCKADDR_IN* addr = (SOCKADDR_IN*)&ConnectRequest->remoteAddressAndPort;
	KdPrint(("[LeafNet] Redirect target: %d.%d.%d.%d:%d\n",
		addr->sin_addr.S_un.S_un_b.s_b1,
		addr->sin_addr.S_un.S_un_b.s_b2,
		addr->sin_addr.S_un.S_un_b.s_b3,
		addr->sin_addr.S_un.S_un_b.s_b4,
		RtlUshortByteSwap(addr->sin_port)));

end0:
	if (!NT_SUCCESS(status)) {
		if (IsCreateClassifyHandle) {
			FwpsReleaseClassifyHandle(ClassifyHandle);
		}

		if (is_proxy) {
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		}
	}

	return;
}

NTSTATUS TcpRedirectpAleCNotify(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER3* filter
) {
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	return STATUS_SUCCESS;
}