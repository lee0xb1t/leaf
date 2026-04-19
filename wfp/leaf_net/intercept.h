#ifndef __INTERCEPT_H
#define __INTERCEPT_H

#include "driver.h"

typedef struct INTERCEPT_FLOW_CONTEXT_
{
    LIST_ENTRY list_entry;
    ADDRESS_FAMILY address_family;

#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION
    union
    {
        FWP_BYTE_ARRAY16 local_addr;
        UINT32 ipv4_local_addr;
    };
#pragma warning(pop)
    USHORT local_port;


    /*
    * IPPROTO
    */
    UINT8 protocol;

    UINT64 flow_handle;
    UINT16 layer_id;
    UINT32 callout_id;

    UINT32 ipv4NetworkOrderStorage;

#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION
    union
    {
        FWP_BYTE_ARRAY16 remote_addr;
        UINT32 ipv4_remote_addr;
    };
#pragma warning(pop)
    UINT16 remote_port;

    LONG64 ref_count;

    UINT64 process_id;
    FWP_DIRECTION direction;

    BOOLEAN removed_from_head;
} INTERCEPT_FLOW_CONTEXT, *PINTERCEPT_FLOW_CONTEXT;


VOID InterceptInit();
VOID InterceptDestroy();

void InterceptFlowEstablishedClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

NTSTATUS InterceptFlowEstablishedNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter
);

void InterceptTransportClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

NTSTATUS InterceptTransportNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter
);

void InterceptTransportFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
);

#endif