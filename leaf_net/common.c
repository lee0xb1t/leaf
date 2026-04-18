#include "common.h"

BOOL CommonIsIpv4LAN(UINT32 v4_addr) {
    UINT32 remoteAddr = v4_addr;
    
    if ((remoteAddr & 0x000000FF) == 0x0000000A || // 10.x.x.x
        ((remoteAddr & 0x0000F0FF) == 0x000010AC && (remoteAddr & 0x0000FF00) >= 0x00000010 && (remoteAddr & 0x0000FF00) <= 0x0000001F) || // 172.16-31.x.x
        ((remoteAddr & 0x0000FFFF) == 0x0000A8C0)) // 192.168.x.x
    {
        return TRUE;
    }

    return FALSE;
}

BOOL CommonIsIpv6LAN(FWP_BYTE_ARRAY16* v6_addr) {
    FWP_BYTE_ARRAY16* ipv6Addr = v6_addr;

    if (!ipv6Addr) return FALSE;

    const UINT8* addr = ipv6Addr->byteArray16;

    // 1. 回环地址 ::1/128
    //    除了最后一个字节是 0x01，前面 15 个字节全为 0
    BOOL isLoopback = TRUE;
    for (int i = 0; i < 15; i++) {
        if (addr[i] != 0) {
            isLoopback = FALSE;
            break;
        }
    }
    if (isLoopback && addr[15] == 0x01) {
        return TRUE; // ::1
    }

    // 2. 链路本地地址 FE80::/10
    //    第一个字节必须是 0xFE
    //    第二个字节的高两位必须是 10 (即范围 0x80 ~ 0xBF)
    if (addr[0] == 0xFE) {
        UINT8 secondByte = addr[1];
        // 检查高两位是否为 10 (0x80 ~ 0xBF)
        if ((secondByte & 0xC0) == 0x80) {
            return TRUE; // FE80::/10
        }
    }

    // 3. 唯一本地地址 FC00::/7
    //    第一个字节的高 7 位必须是 1111110 (即 0xFC 或 0xFD)
    //    (addr[0] & 0xFE) == 0xFC 也可以
    if (addr[0] == 0xFC || addr[0] == 0xFD) {
        return TRUE; // FC00::/7 (实际常用 FD00::/8)
    }

    // 4. 组播地址 FF00::/8 (可选，取决于你的需求)
    if (addr[0] == 0xFF) {
        return TRUE; // FF00::/8 所有组播地址
        // 如果只想拦截特定范围的组播（如链路本地组播 FF02::/16），可进一步判断：
        // if (addr[1] == 0x02) return true; // 仅链路本地组播
    }

    // 5. IPv4 映射地址 ::FFFF:0:0/96 (可选)
    //    前 10 个字节为 0，第 11、12 字节为 0xFF
    //    通常不需要拦截，因为这是 IPv4 流量，会走 V4 层
    BOOL isIPv4Mapped = TRUE;
    for (int i = 0; i < 10; i++) {
        if (addr[i] != 0) {
            isIPv4Mapped = FALSE;
            break;
        }
    }
    if (isIPv4Mapped && addr[10] == 0xFF && addr[11] == 0xFF) {
        // 这是 IPv4 映射地址，真正的 IPv4 地址在后 4 字节
        // 可以提取后 4 字节用 IPv4 规则再判断一次
        // UINT32 ipv4 = *(UINT32*)(addr + 12);
        // return IsIPv4LocalAddress(ipv4);
        return FALSE;
    }

    return FALSE;
}

USHORT CommonGetWfpAddressType(
    const FWPS_INCOMING_VALUES* inFixedValues,
    UINT32 layerId
) {
    NL_ADDRESS_TYPE addressType = NlatUnspecified;
    UINT32 fieldId = 0;

    switch (layerId)
    {
        // ipv4
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
        fieldId = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_DESTINATION_ADDRESS_TYPE;
        break;
    case FWPS_LAYER_ALE_CONNECT_REDIRECT_V4:
        fieldId = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_DESTINATION_ADDRESS_TYPE;
        break;

    case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
        fieldId = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_DESTINATION_ADDRESS_TYPE;
        break;

       // ipv6
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6:
        fieldId = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_DESTINATION_ADDRESS_TYPE;
        break;

    case FWPS_LAYER_ALE_CONNECT_REDIRECT_V6:
        fieldId = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_DESTINATION_ADDRESS_TYPE;
        break;

    case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
        fieldId = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_DESTINATION_ADDRESS_TYPE;
        break;

    default:
        return addressType;
    }
    
    addressType = (NL_ADDRESS_TYPE)inFixedValues->incomingValue[fieldId].value.uint8;
    return addressType;
}

BOOL CommonIsLAN(
    const FWPS_INCOMING_VALUES* inFixedValues,
    UINT32 layerId,
    const PVOID remoteAddr
) {
    NL_ADDRESS_TYPE addrType = CommonGetWfpAddressType(inFixedValues, layerId);

    if (addrType == NlatMulticast ||
        addrType == NlatBroadcast ||
        addrType == NlatAnycast)
    {
        return TRUE;
    }

    if (addrType == NlatUnicast && remoteAddr)
    {
        if (layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4 ||
            layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4)
        {
            return CommonIsIpv4LAN(*(UINT32*)remoteAddr);
        }
        else if (layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6 ||
            layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6)
        {
            return CommonIsIpv6LAN((FWP_BYTE_ARRAY16*)remoteAddr);
        }
    }

    return FALSE;
}