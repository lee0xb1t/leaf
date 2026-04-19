// userapp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#define WIN32_LEAN_AND_MEAN  
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>        
#include <Ws2def.h>          
#include <Ws2ipdef.h>        
#include <Mstcpip.h>         
#include <Windows.h>         

#include <WinIoCtl.h>

#include <iostream>

#include <cstdio>
#include <cstdlib>

#pragma comment(lib, "Ws2_32.lib")



#define IOCTL_ADDPROXY_SELF CTL_CODE(FILE_DEVICE_UNKNOWN, 0x001, METHOD_BUFFERED, FILE_ANY_ACCESS)

int func()
{
    bool ok = false;

    HANDLE hDevice = CreateFile(
        L"\\\\.\\Leaf_NetFilter",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "GetLastError: " << std::hex << GetLastError() << std::endl;
        // system("pause");
        return -1;
    }

    std::cout << "文件打开正常!\n";

    DWORD dwRet = 0;
    ok = DeviceIoControl(hDevice, IOCTL_ADDPROXY_SELF, NULL, 0, NULL, 0, &dwRet, 0);
    if (ok) {
        printf("dwRet: %d\n", dwRet);
    }

    CloseHandle(hDevice);
}

#define CONTEXT_SIZE sizeof(SOCKADDR_STORAGE)

int listen() {
    WSADATA wsaData;
    SOCKET listenSock = INVALID_SOCKET;
    SOCKET clientSock = INVALID_SOCKET;
    struct sockaddr_in addr;
    int result;

    // 1. 初始化 Winsock
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("[代理] WSAStartup 失败: %d\n", result);
        return -1;
    }
    printf("[代理] Winsock 初始化成功\n");

    // 2. 创建 socket
    listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        printf("[代理] socket 失败: %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    // 3. 绑定到 127.0.0.1:8888
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8888);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");  // 关键：必须是 127.0.0.1

    result = bind(listenSock, (struct sockaddr*)&addr, sizeof(addr));
    if (result == SOCKET_ERROR) {
        printf("[代理] bind 失败: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return -1;
    }
    printf("[代理] 绑定到 127.0.0.1:8888 成功\n");

    // 4. 监听
    result = listen(listenSock, SOMAXCONN);
    if (result == SOCKET_ERROR) {
        printf("[代理] listen 失败: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return -1;
    }
    printf("[代理] 开始监听...\n");

    // 5. 接受连接循环
    while (1) {
        clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET) {
            printf("[代理] accept 失败: %d\n", WSAGetLastError());
            continue;
        }
        printf("[代理] ===== 接受新连接，socket: %d =====\n", (int)clientSock);

        // 6. 接收数据
        char buffer[4096];
        int recvLen = recv(clientSock, buffer, sizeof(buffer) - 1, 0);
        if (recvLen > 0) {
            buffer[recvLen] = '\0';
            printf("[代理] 收到 %d 字节:\n%s\n", recvLen, buffer);

            // 7. 发送响应（HTTP 代理示例）
            const char* response =
                "HTTP/1.1 200 Connection Established\r\n"
                "Proxy-Agent: LeafNetProxy\r\n"
                "\r\n";
            send(clientSock, response, (int)strlen(response), 0);
            printf("[代理] 已发送响应\n");
        }

        closesocket(clientSock);
    }

    closesocket(listenSock);
    WSACleanup();


    //------------------------------------------------------------

    //// --- 步骤 3 & 4: 查询 WFP 重定向信息 ---
    SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS;
    //// 3. 先查询重定向记录 (redirect records)
    //// 第一次调用，获取所需缓冲区大小
    //result = WSAIoctl(
    //    clientSock,
    //    SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
    //    NULL, 0,
    //    &redirectRecordsSize, sizeof(redirectRecordsSize),
    //    &bytesReturned,
    //    NULL, NULL
    //);
    //// 期望失败，错误码为 WSAEFAULT 或 WSAEINVAL，但 bytesReturned 应为 0 或具体大小。
    //// 一个更健壮的实践是分配一个足够大的初始缓冲区 (例如 1KB) 以避免两次调用。

    //// 分配并真正获取重定向记录
    //redirectRecords = (BYTE*)malloc(redirectRecordsSize);
    //if (!redirectRecords) {
    //    goto cleanup;
    //}

    //result = WSAIoctl(
    //    clientSock,
    //    SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
    //    NULL, 0,
    //    redirectRecords, redirectRecordsSize,
    //    &bytesReturned,
    //    NULL, NULL
    //);
    //if (result == SOCKET_ERROR) {
    //    // 错误处理: 可能是连接未被 WFP 重定向
    //    goto cleanup;
    //}
    //// redirectRecords 中现在包含了驱动设置的不透明数据，可用于验证或关联 
    setsockopt;
    //// 4. 查询重定向上下文 (redirect context)，它包含了原始目标地址
    //// WFP 会将原始目标地址/端口放在此上下文的开头
    //result = WSAIoctl(
    //    clientSock,
    //    SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
    //    NULL, 0,
    //    redirectContext, sizeof(redirectContext), // 你的 CONTEXT_SIZE 必须足够大
    //    &bytesReturned,
    //    NULL, NULL
    //);
    //if (result == SOCKET_ERROR) {
    //    // 如果失败 (例如 WSAEINVAL)，请确保驱动在重定向时设置了正确的标志
    //    // 例如 FWPS_CLASSIFY_OUT_FLAG_ALE_CONNECT_REDIRECT 并且修改了 remoteAddressAndPort
    //    goto cleanup;
    //}

    //// 5. 从 redirectContext 中提取原始目标 IP 和端口
    //if (bytesReturned >= sizeof(SOCKADDR_STORAGE)) {
    //    // 上下文数据的开头通常是原始目标地址的 SOCKADDR 结构 [citation:7]
    //    SOCKADDR_STORAGE* pOriginalDest = (SOCKADDR_STORAGE*)redirectContext;

    //    // 提取IP和端口
    //    if (pOriginalDest->ss_family == AF_INET) {
    //        SOCKADDR_IN* pAddrIn = (SOCKADDR_IN*)pOriginalDest;
    //        // 原始目标 IP:
    //        IN_ADDR originalIP = pAddrIn->sin_addr;
    //        // 原始目标端口 (网络字节序，需转为主机序):
    //        USHORT originalPort = ntohs(pAddrIn->sin_port);

    //        printf("Original destination: %s:%d\n", inet_ntoa(originalIP), originalPort);
    //    }
    //    else if (pOriginalDest->ss_family == AF_INET6) {
    //        SOCKADDR_IN6* pAddrIn6 = (SOCKADDR_IN6*)pOriginalDest;
    //        // ... 处理 IPv6 地址
    //    }
    //}

}

#include <thread>

int main() {
    std::thread t([&]() {
        printf("in thread\n");
        listen();
    });
    func();
    t.join();
    system("pause");
}


