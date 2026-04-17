#include "leafnet.h"
#include "intercept.h"
#include "tcp/redirect.h"


//
// Variables
//

HANDLE g_WfpHandle = NULL;

HANDLE g_NetworkInjectionHandle = NULL;

UINT32 g_TransportV4InboundCalloutId = 0;
UINT32 g_TransportV4OutboundCalloutId = 0;

UINT32 g_TransportV6InboundCalloutId = 0;
UINT32 g_TransportV6OutboundCalloutId = 0;


//
// Prototypes
//

NTSTATUS LeafNetpRegisterInterceptFlowEstablishedCallout(
	IN OUT PDEVICE_OBJECT DeviceObj,
	IN const GUID* pLayerKey,
	IN const GUID* pCalloutKey,
	IN const GUID* pInBoundFilterKey,
	IN const GUID* pOutBoundFilterKey
);

NTSTATUS LeafNetpRegisterInterceptTransportCallout(
	IN OUT PDEVICE_OBJECT DeviceObj,

	IN const GUID* pInBoundLayerKey,
	IN const GUID* pInBoundCalloutKey,
	IN const GUID* pInBoundFilterKey,
	OUT UINT32* pInBoundCalloutId,

	IN const GUID* pOutBoundLayerKey,
	IN const GUID* pOutBoundCalloutKey,
	IN const GUID* pOutBoundFilterKey,
	OUT UINT32* pOutBoundCalloutId
);

NTSTATUS LeafNetpAddFilter(
	IN PCWCHAR Name,
	IN PCWCHAR Description,
	IN FWP_DIRECTION Direction,
	IN UINT64 Context,
	IN const GUID* pLayerKey,
	IN const GUID* pCalloutKey,
	IN const GUID* pFilterKey
);


//
// Implements
//

NTSTATUS LeafNetInit(IN WDFDEVICE WdfDevice) {
	NTSTATUS status = STATUS_SUCCESS;

	BOOLEAN engineOpened = FALSE;
	BOOLEAN inTransaction = FALSE;
	BOOLEAN injectionHandleCreated = FALSE;
	BOOL IsProviderAdded = FALSE;
	BOOL IsTcpRedirectInited = FALSE;

	FWPM_SESSION session = { 0 };

	InterceptInit();

	DbgBreakPoint();
	
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	status = FwpsInjectionHandleCreate(AF_UNSPEC, FWPS_INJECTION_TYPE_TRANSPORT, &g_NetworkInjectionHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Network injection handle create fialed, status = 0x%x\n", status));
		goto end0;
	}

	injectionHandleCreated = TRUE;

	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_WfpHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp engine open failed, status = 0x%x\n", status));
		goto end0;
	}

	engineOpened = TRUE;

	status = FwpmTransactionBegin(g_WfpHandle, 0);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp transaction begin failed, status = 0x%x\n", status));
		goto end0;
	}

	inTransaction = TRUE;

	status = LeafNetAddProvider(g_WfpHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp provider add failed(ignored), status = 0x%x\n", status));
	}

	IsProviderAdded = TRUE;

	status = LeafNetRegisterSublayer(WdfDevice, &LEAFNET_PROVIDER);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp register sublayer failed, status = 0x%x\n", status));
		goto end0;
	}

	//status = LeafNetRegisterInterceptCallouts(WdfDevice);
	//if (!NT_SUCCESS(status)) {
	//	KdPrint(("[LeafNet] Wfp register callouts failed, status = 0x%x\n", status));
	//	goto end0;
	//}

	// tcp redirect

	status = TcpRedirectInit(g_WfpHandle, WdfDevice, &LEAFNET_PROVIDER, &LEAFNET_SUB_LAYER);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Tcp redirect init failed, status = 0x%x\n", status));
		goto end0;
	}
	IsTcpRedirectInited = TRUE;

	status = FwpmTransactionCommit(g_WfpHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp transaction commit failed, status = 0x%x\n", status));
		goto end0;
	}

	inTransaction = FALSE;

end0:
	if (!NT_SUCCESS(status)) {
		if (inTransaction) {
			FwpmTransactionAbort(g_WfpHandle);
			_Analysis_assume_lock_not_held_(g_WfpHandle); // Potential leak if "FwpmTransactionAbort" fails
		}

		if (engineOpened) {
			if (IsTcpRedirectInited) {
				TcpRedirectDestroy(g_WfpHandle);
			}

			LeafNetUnRegisterInterceptCallouts();

			if (IsProviderAdded) {
				FwpmProviderDeleteByKey(g_WfpHandle, &LEAFNET_PROVIDER);
			}

			FwpmEngineClose(g_WfpHandle);
			g_WfpHandle = NULL;
		}

		if (injectionHandleCreated) {
			FwpsInjectionHandleDestroy(g_NetworkInjectionHandle);
		}
	}

	return status;
}

VOID LeafNetDestroy() {
	InterceptDestroy();

	if (g_WfpHandle) {
		LeafNetUnRegisterInterceptCallouts();

		TcpRedirectDestroy(g_WfpHandle);

		NTSTATUS status = FwpmProviderDeleteByKey(g_WfpHandle, &LEAFNET_PROVIDER);
		DbgBreakPoint();
		KdPrint(("%d\n", status));

		FwpmEngineClose(g_WfpHandle);
		g_WfpHandle = NULL;
	}

	if (g_NetworkInjectionHandle) {
		FwpsInjectionHandleDestroy(g_NetworkInjectionHandle);
		g_NetworkInjectionHandle = NULL;
	}
}

NTSTATUS LeafNetAddProvider(IN WDFDEVICE WdfDevice) {
	UNREFERENCED_PARAMETER(WdfDevice);

	NTSTATUS status = STATUS_SUCCESS;

	FWPM_PROVIDER provider = { 0 };
	provider.displayData.name = LeafNetProviderName;
	provider.displayData.description = LeafNetProviderDesc;
	provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
	provider.providerKey = LEAFNET_PROVIDER;
	status = FwpmProviderAdd(g_WfpHandle, &provider, NULL);
	return status;
}

NTSTATUS LeafNetRegisterSublayer(IN WDFDEVICE WdfDevice, IN const GUID* ProviderKey) {
	UNREFERENCED_PARAMETER(WdfDevice);

	NTSTATUS status = STATUS_SUCCESS;
	FWPM_SUBLAYER SubLayer = { 0 };

	RtlZeroMemory(&SubLayer, sizeof(FWPM_SUBLAYER));

	SubLayer.subLayerKey = LEAFNET_SUB_LAYER;
	SubLayer.displayData.name = LeafNetSubLayerName;
	SubLayer.displayData.description = LeafNetSubLayerDesc;
	SubLayer.flags = 0;
	SubLayer.weight = FWP_EMPTY; // auto-weight.
	SubLayer.providerKey = (GUID*)ProviderKey;

	status = FwpmSubLayerAdd(g_WfpHandle, &SubLayer, NULL);

	return status;
}

NTSTATUS LeafNetRegisterInterceptCallouts(IN WDFDEVICE WdfDevice) {
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObj = NULL;

	DeviceObj = WdfDeviceWdmGetDeviceObject(WdfDevice);

	if (!DeviceObj) {
		return STATUS_INVALID_DEVICE_OBJECT_PARAMETER;
	}

	status = LeafNetpRegisterInterceptFlowEstablishedCallout(
		DeviceObj,
		&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
		&INTERCEPT_FLOW_ESTABLISHED_V4_CALLOUT,
		&INTERCEPT_INBOUND_FLOW_ESTABLISHED_V4_FILTER,
		&INTERCEPT_OUTBOUND_FLOW_ESTABLISHED_V4_FILTER
	);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp register interpect flow established V4 callout failed, status = 0x%x\n", status));
		goto end0;
	}

	status = LeafNetpRegisterInterceptFlowEstablishedCallout(
		DeviceObj,
		&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
		&INTERCEPT_FLOW_ESTABLISHED_V6_CALLOUT,
		&INTERCEPT_INBOUND_FLOW_ESTABLISHED_V6_FILTER,
		&INTERCEPT_OUTBOUND_FLOW_ESTABLISHED_V6_FILTER
	);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp register example flow established V6 callout failed, status = 0x%x\n", status));
		goto end0;
	}

	status = LeafNetpRegisterInterceptTransportCallout(
		DeviceObj,

		&FWPM_LAYER_INBOUND_TRANSPORT_V4,
		&INTERCEPT_INBOUND_TRANSPORT_V4_CALLOUT,
		&INTERCEPT_INBOUND_TRANSPORT_V4_FILTER,
		&g_TransportV4InboundCalloutId,

		&FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		&INTERCEPT_OUTBOUND_TRANSPORT_V4_CALLOUT,
		&INTERCEPT_OUTBOUND_TRANSPORT_V4_FILTER,
		&g_TransportV4OutboundCalloutId
	);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp register intercept transport V4 callout failed, status = 0x%x\n", status));
		goto end0;
	}

	status = LeafNetpRegisterInterceptTransportCallout(
		DeviceObj,

		&FWPM_LAYER_INBOUND_TRANSPORT_V6,
		& INTERCEPT_INBOUND_TRANSPORT_V6_CALLOUT,
		&INTERCEPT_INBOUND_TRANSPORT_V6_FILTER,
		&g_TransportV6InboundCalloutId,

		&FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
		& INTERCEPT_OUTBOUND_TRANSPORT_V6_CALLOUT,
		&INTERCEPT_OUTBOUND_TRANSPORT_V6_FILTER,
		&g_TransportV6OutboundCalloutId
	);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp register intercept transport V4 callout failed, status = 0x%x\n", status));
		goto end0;
	}

end0:
	return status;
}

VOID LeafNetUnRegisterInterceptCallouts() {
	// Filters
	FwpmFilterDeleteByKey(g_WfpHandle, &INTERCEPT_OUTBOUND_TRANSPORT_V6_FILTER);
	FwpmFilterDeleteByKey(g_WfpHandle, &INTERCEPT_INBOUND_TRANSPORT_V6_FILTER);
	FwpmFilterDeleteByKey(g_WfpHandle, &INTERCEPT_OUTBOUND_TRANSPORT_V4_FILTER);
	FwpmFilterDeleteByKey(g_WfpHandle, &INTERCEPT_INBOUND_TRANSPORT_V4_FILTER);
	FwpmFilterDeleteByKey(g_WfpHandle, &INTERCEPT_INBOUND_FLOW_ESTABLISHED_V6_FILTER);
	FwpmFilterDeleteByKey(g_WfpHandle, &INTERCEPT_OUTBOUND_FLOW_ESTABLISHED_V6_FILTER);
	FwpmFilterDeleteByKey(g_WfpHandle, &INTERCEPT_INBOUND_FLOW_ESTABLISHED_V4_FILTER);
	FwpmFilterDeleteByKey(g_WfpHandle, &INTERCEPT_OUTBOUND_FLOW_ESTABLISHED_V4_FILTER);

	// Callouts
	FwpsCalloutUnregisterByKey(&INTERCEPT_INBOUND_TRANSPORT_V6_CALLOUT);
	FwpsCalloutUnregisterByKey(&INTERCEPT_OUTBOUND_TRANSPORT_V6_CALLOUT);
	FwpsCalloutUnregisterByKey(&INTERCEPT_INBOUND_TRANSPORT_V4_CALLOUT);
	FwpsCalloutUnregisterByKey(&INTERCEPT_OUTBOUND_TRANSPORT_V4_CALLOUT);
	FwpsCalloutUnregisterByKey(&INTERCEPT_FLOW_ESTABLISHED_V6_CALLOUT);
	FwpsCalloutUnregisterByKey(&INTERCEPT_FLOW_ESTABLISHED_V4_CALLOUT);

	FwpmCalloutDeleteByKey(g_WfpHandle, &INTERCEPT_INBOUND_TRANSPORT_V6_CALLOUT);
	FwpmCalloutDeleteByKey(g_WfpHandle, &INTERCEPT_OUTBOUND_TRANSPORT_V6_CALLOUT);
	FwpmCalloutDeleteByKey(g_WfpHandle, &INTERCEPT_INBOUND_TRANSPORT_V4_CALLOUT);
	FwpmCalloutDeleteByKey(g_WfpHandle, &INTERCEPT_OUTBOUND_TRANSPORT_V4_CALLOUT);
	FwpmCalloutDeleteByKey(g_WfpHandle, &INTERCEPT_FLOW_ESTABLISHED_V6_CALLOUT);
	FwpmCalloutDeleteByKey(g_WfpHandle, &INTERCEPT_FLOW_ESTABLISHED_V4_CALLOUT);

	// Sublayers
	FwpmSubLayerDeleteByKey(g_WfpHandle, &LEAFNET_SUB_LAYER);
}

NTSTATUS LeafNetpRegisterInterceptFlowEstablishedCallout(
	IN OUT PDEVICE_OBJECT DeviceObj,
	IN const GUID* pLayerKey,
	IN const GUID* pCalloutKey,
	IN const GUID* pInBoundFilterKey,
	IN const GUID* pOutBoundFilterKey
) {
	NTSTATUS status = STATUS_SUCCESS;

	FWPS_CALLOUT sCallout = { 0 };
	FWPM_CALLOUT mCallout = { 0 };

	FWPM_DISPLAY_DATA displayData = { 0 };


	// Callouts

	sCallout.calloutKey = *pCalloutKey;
	sCallout.classifyFn = InterceptFlowEstablishedClassify;
	sCallout.notifyFn = InterceptFlowEstablishedNotify;

	status = FwpsCalloutRegister(DeviceObj, &sCallout, NULL);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp register callout failed, status = 0x%x\n", status));
		goto end0;
	}

	displayData.name = L"Intercept flow-established callout";
	displayData.description = L"Intercept flow-established callout";

	mCallout.calloutKey = *pCalloutKey;
	mCallout.applicableLayer = *pLayerKey;
	mCallout.displayData = displayData;

	status = FwpmCalloutAdd(g_WfpHandle, &mCallout, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp add callout failed, status = 0x%x\n", status));
		goto end0;
	}

	// Filters

	status = LeafNetpAddFilter(
		L"Intercept outbound flow-established",
		L"Intercept outbound flow-established",
		FWP_DIRECTION_OUTBOUND,
		0,
		pLayerKey,
		pCalloutKey,
		pOutBoundFilterKey
	);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp add outbound filter failed, status = 0x%x\n", status));
		goto end0;
	}

	status = LeafNetpAddFilter(
		L"Intercept inbound flow-established",
		L"Intercept inbound flow-established",
		FWP_DIRECTION_INBOUND,
		0,
		pLayerKey,
		pCalloutKey,
		pInBoundFilterKey
	);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wfp add inbound filter failed, status = 0x%x\n", status));
		goto end0;
	}

end0:
	if (!NT_SUCCESS(status)) {
		FwpmFilterDeleteByKey(g_WfpHandle, pOutBoundFilterKey);
		FwpmFilterDeleteByKey(g_WfpHandle, pInBoundFilterKey);

		FwpsCalloutUnregisterByKey(pCalloutKey);
		FwpmCalloutDeleteByKey(g_WfpHandle, pCalloutKey);
	}

	return status;
}

NTSTATUS LeafNetpRegisterInterceptTransportCallout(
	IN OUT PDEVICE_OBJECT DeviceObj,

	IN const GUID* pInBoundLayerKey,
	IN const GUID* pInBoundCalloutKey,
	IN const GUID* pInBoundFilterKey,
	OUT UINT32* pInBoundCalloutId,

	IN const GUID* pOutBoundLayerKey,
	IN const GUID* pOutBoundCalloutKey,
	IN const GUID* pOutBoundFilterKey,
	OUT UINT32* pOutBoundCalloutId
)
{
	NTSTATUS status = STATUS_SUCCESS;

	FWPS_CALLOUT i_sCallout = { 0 };
	FWPM_CALLOUT i_mCallout = { 0 };

	FWPS_CALLOUT o_sCallout = { 0 };
	FWPM_CALLOUT o_mCallout = { 0 };

	FWPM_DISPLAY_DATA i_displayData = { 0 };
	FWPM_DISPLAY_DATA o_displayData = { 0 };

	if (pInBoundLayerKey) {
		i_sCallout.calloutKey = *pInBoundCalloutKey;
		i_sCallout.classifyFn = InterceptTransportClassify;
		i_sCallout.notifyFn = InterceptTransportNotify;
		i_sCallout.flowDeleteFn = InterceptTransportFlowDelete;

		status = FwpsCalloutRegister(DeviceObj, &i_sCallout, pInBoundCalloutId);
		if (!NT_SUCCESS(status)) {
			KdPrint(("[LeafNet] Wfp register callout failed, status = 0x%x\n", status));
			goto end0;
		}

		i_displayData.name = L"Intercept inbound transport callout";
		i_displayData.description = L"Intercept inbound transport callout";

		i_mCallout.calloutKey = *pInBoundCalloutKey;
		i_mCallout.applicableLayer = *pInBoundLayerKey;
		i_mCallout.displayData = i_displayData;

		status = FwpmCalloutAdd(g_WfpHandle, &i_mCallout, NULL, NULL);
		if (!NT_SUCCESS(status)) {
			KdPrint(("[LeafNet] Wfp add inbound transport callout failed, status = 0x%x\n", status));
			goto end0;
		}

		status = LeafNetpAddFilter(
			L"Intercept inbound transport filter",
			L"Intercept inbound transport filter",
			FWP_DIRECTION_INBOUND,
			0,
			pInBoundLayerKey,
			pInBoundCalloutKey,
			pInBoundFilterKey
		);
		if (!NT_SUCCESS(status)) {
			KdPrint(("[LeafNet] Wfp add inbound transport filter failed, status = 0x%x\n", status));
			goto end0;
		}
	}
	
	
	if (pOutBoundLayerKey) {
		o_sCallout.calloutKey = *pOutBoundCalloutKey;
		o_sCallout.classifyFn = InterceptTransportClassify;
		o_sCallout.notifyFn = InterceptTransportNotify;
		o_sCallout.flowDeleteFn = InterceptTransportFlowDelete;

		status = FwpsCalloutRegister(DeviceObj, &o_sCallout, pOutBoundCalloutId);
		if (!NT_SUCCESS(status)) {
			KdPrint(("[LeafNet] Wfp register callout failed, status = 0x%x\n", status));
			goto end0;
		}

		o_displayData.name = L"Intercept outbound transport callout";
		o_displayData.description = L"Intercept outbound transport callout";

		o_mCallout.calloutKey = *pOutBoundCalloutKey;
		o_mCallout.applicableLayer = *pOutBoundLayerKey;
		o_mCallout.displayData = o_displayData;

		status = FwpmCalloutAdd(g_WfpHandle, &o_mCallout, NULL, NULL);
		if (!NT_SUCCESS(status)) {
			KdPrint(("[LeafNet] Wfp add outbound transport callout failed, status = 0x%x\n", status));
			goto end0;
		}

		status = LeafNetpAddFilter(
			L"Intercept outbound transport filter",
			L"Intercept outbound transport filter",
			FWP_DIRECTION_MAX,
			0,
			pOutBoundLayerKey,
			pOutBoundCalloutKey,
			pOutBoundFilterKey
		);
		if (!NT_SUCCESS(status)) {
			KdPrint(("[LeafNet] Wfp add outbound transport filter failed, status = 0x%x\n", status));
			goto end0;
		}
	}

end0:
	if (!NT_SUCCESS(status)) {
		FwpmFilterDeleteByKey(g_WfpHandle, pInBoundFilterKey);
		FwpsCalloutUnregisterByKey(pInBoundCalloutKey);
		FwpmCalloutDeleteByKey(g_WfpHandle, pInBoundCalloutKey);

		FwpmFilterDeleteByKey(g_WfpHandle, pOutBoundFilterKey);
		FwpsCalloutUnregisterByKey(pOutBoundCalloutKey);
		FwpmCalloutDeleteByKey(g_WfpHandle, pOutBoundCalloutKey);
	}

	return status;
}

NTSTATUS LeafNetpAddFilter(
	IN PCWCHAR Name,
	IN PCWCHAR Description,
	IN FWP_DIRECTION Direction,
	IN UINT64 Context,
	IN const GUID* pLayerKey,
	IN const GUID* pCalloutKey,
	IN const GUID* pFilterKey
) 
{
	NTSTATUS status = STATUS_SUCCESS;

	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION filterConditions[3] = { 0 };
	UINT conditionIndex = 0;

	filter.layerKey = *pLayerKey;
	filter.displayData.name = (PWCHAR)Name;
	filter.displayData.description = (PWCHAR)Description;

	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = *pCalloutKey;
	filter.filterCondition = filterConditions;
	filter.subLayerKey = LEAFNET_SUB_LAYER;
	filter.weight.type = FWP_EMPTY; // auto-weight
	filter.rawContext = Context;
	filter.filterKey = *pFilterKey;

	if (IsEqualGUID(pLayerKey, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4) ||
		IsEqualGUID(pLayerKey, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6))
	{
		filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_DIRECTION;
		filterConditions[conditionIndex].matchType = FWP_MATCH_EQUAL;
		filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
		filterConditions[conditionIndex].conditionValue.uint32 = Direction;
		++conditionIndex;
	}

	filter.numFilterConditions = conditionIndex;

	status = FwpmFilterAdd(
		g_WfpHandle,
		&filter,
		NULL,
		NULL
	);

	return status;
}