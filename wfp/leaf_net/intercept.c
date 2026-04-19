#include "intercept.h"


//
// Varibales
//
BOOLEAN g_IsDestroy = FALSE;

LIST_ENTRY g_FlowList;
KSPIN_LOCK g_FlowListLock;

//
// Extern
//

extern UINT32 g_TransportV4InboundCalloutId;
extern UINT32 g_TransportV4OutboundCalloutId;

extern UINT32 g_TransportV6InboundCalloutId;
extern UINT32 g_TransportV6OutboundCalloutId;


//
// Prototypes
//

VOID FlowContextReference(IN OUT PINTERCEPT_FLOW_CONTEXT FlowContext);
VOID FlowContextDereference(IN OUT PINTERCEPT_FLOW_CONTEXT FlowContext);


//
// Implements
//

VOID InterceptInit() {
    InitializeListHead(&g_FlowList);
    KeInitializeSpinLock(&g_FlowListLock);
}

VOID InterceptDestroy() {
    KLOCK_QUEUE_HANDLE LockQueueHandle;
    PLIST_ENTRY entry;

    KeAcquireInStackQueuedSpinLock(&g_FlowListLock, &LockQueueHandle);

    g_IsDestroy = TRUE;

    while (!IsListEmpty(&g_FlowList)) {
        entry = RemoveHeadList(&g_FlowList);

        KeReleaseInStackQueuedSpinLock(&LockQueueHandle);

        PINTERCEPT_FLOW_CONTEXT ctx = CONTAINING_RECORD(entry, INTERCEPT_FLOW_CONTEXT, list_entry);

        ctx->removed_from_head = TRUE;

        FwpsFlowRemoveContext(
            ctx->flow_handle,
            ctx->layer_id,
            ctx->callout_id
        );

        KeAcquireInStackQueuedSpinLock(&g_FlowListLock, &LockQueueHandle);
    }

    KeReleaseInStackQueuedSpinLock(&LockQueueHandle);
}

void InterceptFlowEstablishedClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(flowContext);
    
    NTSTATUS status = STATUS_SUCCESS;
    PINTERCEPT_FLOW_CONTEXT FlowContext = NULL;
    KLOCK_QUEUE_HANDLE FlowListLockHandle;
    BOOLEAN IsLocked = FALSE;

    FlowContext = ExAllocatePool3(POOL_FLAG_NON_PAGED, sizeof(INTERCEPT_FLOW_CONTEXT), 'FAEL', NULL, 0);
    if (!FlowContext) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end0;
    }

    RtlZeroMemory(FlowContext, sizeof(INTERCEPT_FLOW_CONTEXT));

    InitializeListHead(&FlowContext->list_entry);

    FlowContext->ref_count = 1;

    FlowContext->direction = inMetaValues->packetDirection;

    FlowContext->address_family = (inFixedValues->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4) ? AF_INET : AF_INET6;

    NT_ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE));
    FlowContext->flow_handle = inMetaValues->flowHandle;

    FlowContext->layer_id = 
        (FlowContext->address_family == AF_INET) 
        ? (inMetaValues->packetDirection == FWP_DIRECTION_INBOUND ? FWPS_LAYER_INBOUND_TRANSPORT_V4  : FWPS_LAYER_OUTBOUND_TRANSPORT_V4) 
        : (inMetaValues->packetDirection == FWP_DIRECTION_INBOUND ? FWPS_LAYER_INBOUND_TRANSPORT_V6 : FWPS_LAYER_OUTBOUND_TRANSPORT_V6);

    FlowContext->callout_id = 
        (FlowContext->address_family == AF_INET)
        ? (inMetaValues->packetDirection == FWP_DIRECTION_INBOUND ? g_TransportV4InboundCalloutId : g_TransportV4OutboundCalloutId)
        : (inMetaValues->packetDirection == FWP_DIRECTION_INBOUND ? g_TransportV6InboundCalloutId : g_TransportV6OutboundCalloutId);

    
    if (FlowContext->address_family == AF_INET) {
        FlowContext->ipv4_local_addr = RtlUlongByteSwap(
            inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32
        );

        FlowContext->local_port = RtlUshortByteSwap(
            inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16
        );

        FlowContext->ipv4_remote_addr = RtlUlongByteSwap(
            inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32
        );

        FlowContext->remote_port = RtlUshortByteSwap(
            inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16
        );

        FlowContext->protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;

    } else {
        NT_ASSERT(FlowContext->address_family == AF_INET6);

        RtlCopyMemory(
            (UINT8*)&FlowContext->local_addr,
            inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16)
        );

        FlowContext->local_port = RtlUshortByteSwap(
            inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT].value.uint16
        );

        RtlCopyMemory(
            (UINT8*)&FlowContext->remote_addr,
            inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16)
        );

        FlowContext->remote_port = RtlUshortByteSwap(
            inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT].value.uint16
        );

        FlowContext->protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint8;
    }

    FlowContext->process_id = inMetaValues->processId;

    KeAcquireInStackQueuedSpinLock(
        &g_FlowListLock,
        &FlowListLockHandle
    );

    IsLocked = TRUE;

    if (!g_IsDestroy) {
        status = FwpsFlowAssociateContext(
            FlowContext->flow_handle,
            FlowContext->layer_id,
            FlowContext->callout_id,
            (UINT64)FlowContext
        );
        if (!NT_SUCCESS(status)) {
            goto end0;
        }

        InsertHeadList(&g_FlowList, &FlowContext->list_entry);
        FlowContext = NULL; // ownership transferred
    }

    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }

end0:
    if (IsLocked) {
        KeReleaseInStackQueuedSpinLock(&FlowListLockHandle);
    }

    if (FlowContext != NULL) {
        ExFreePoolWithTag(FlowContext, 'FAEL');
    }

    if (!NT_SUCCESS(status)) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

NTSTATUS InterceptFlowEstablishedNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

void InterceptTransportClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
) 
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(classifyOut);

    PINTERCEPT_FLOW_CONTEXT FlowContext = (PINTERCEPT_FLOW_CONTEXT)flowContext;
    if (FlowContext) {
        KdPrint(("[LeafNet] Intercept transport, direction = %s, af = %s, pid: 0x%llx\n", 
            (FlowContext->direction == FWP_DIRECTION_INBOUND ? "IN" : "OUT"), 
            (FlowContext->address_family == AF_INET ? "V4" : "V6"),
            FlowContext->process_id
        ));
    }

    classifyOut->actionType = FWP_ACTION_PERMIT;
    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

NTSTATUS InterceptTransportNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

void InterceptTransportFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
) 
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);

    PINTERCEPT_FLOW_CONTEXT FlowContext = (PINTERCEPT_FLOW_CONTEXT)flowContext;

    KLOCK_QUEUE_HANDLE FlowListLockHandle;

    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);

    KeAcquireInStackQueuedSpinLock(
        &g_FlowListLock,
        &FlowListLockHandle
    );

    if (!FlowContext->removed_from_head) {
        RemoveEntryList(&FlowContext->list_entry);
        FlowContext->removed_from_head = TRUE;
    }

    KeReleaseInStackQueuedSpinLock(&FlowListLockHandle);

    FlowContextDereference(FlowContext);
}

VOID FlowContextReference(IN OUT PINTERCEPT_FLOW_CONTEXT FlowContext) {
    InterlockedIncrement64(&FlowContext->ref_count);
    NT_ASSERT(FlowContext->ref_count > 0);
}

VOID FlowContextDereference(IN OUT PINTERCEPT_FLOW_CONTEXT FlowContext) {
    NT_ASSERT(FlowContext->ref_count > 0);
    InterlockedDecrement64(&FlowContext->ref_count);
    if (FlowContext->ref_count == 0) {
        ExFreePoolWithTag(FlowContext, 'FAEL');
    }
}