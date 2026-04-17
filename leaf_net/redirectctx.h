#ifndef __REDIRECTCTX_H
#define __REDIRECTCTX_H

#include "driver.h"

#define RC_DEFAULT_NR_PID		10

typedef USHORT RC_PROTO_TYPE;
enum {
	RC_PROTO_TYPE_TCP = 0,
	RC_PROTO_TYPE_UDP,
};

typedef USHORT RC_PROXY_TYPE;
enum {
	RC_PROXY_TYPE_INCLUDED = 0,
	RC_PROXY_TYPE_EXCLUDED,
};

typedef USHORT RC_PID_TYPE;
enum {
	RC_PID_TYPE_BYPASS = 0,
	RC_PID_TYPE_PROXY,
};

typedef struct _REDIRECT_CONTEXT{
	RC_PROTO_TYPE proto_type;
	RC_PROXY_TYPE proxy_type;

	UINT32 nr_bypass_total;
	UINT32 nr_bypass;
	// Processes that are never proxied; can be used for proxy service programs. Array of HANDLEs.
	HANDLE* bypass_pids;

	UINT32 nr_proxy_total;
	UINT32 nr_proxy;
	// Interpretation depends on RR_PROXY_TYPE:
	// RR_PROXY_TYPE_INCLUDED: proxy only proxy_pids;
	// RR_PROXY_TYPE_EXCLUDED: proxy all except proxy_pids.
	HANDLE* proxy_pids;

	USHORT proxy_port;
}REDIRECT_CONTEXT;


NTSTATUS RedirectCtxInit();
NTSTATUS RedirectCtxInit2(RC_PROTO_TYPE ProtocolType);
VOID RedirectCtxDestroy();
VOID RedirectCtxDestroy2(RC_PROTO_TYPE ProtocolType);
NTSTATUS RedirectCtxReInit(RC_PROTO_TYPE ProtocolType);

VOID RedirectCtxSetProxyType(RC_PROTO_TYPE ProtocolType, RC_PROXY_TYPE ProxyType);

NTSTATUS RedirectCtxAddPid(RC_PROTO_TYPE ProtocolType, RC_PID_TYPE PidType, const HANDLE pid);

NTSTATUS RedirectCtxAddBypassPid(RC_PROTO_TYPE ProtocolType, const HANDLE pid);
NTSTATUS RedirectCtxAddProxyPid(RC_PROTO_TYPE ProtocolType, const HANDLE pid);

HANDLE RedirectCtxGetFirstBypassPid(RC_PROTO_TYPE ProtocolType);

BOOL RedirectCtxIsBypassProcess(RC_PROTO_TYPE ProtocolType, const HANDLE pid);
BOOL RedirectCtxIsProxyProcess(RC_PROTO_TYPE ProtocolType, const HANDLE pid);

RC_PROXY_TYPE RedirectCtxGetProxyType(RC_PROTO_TYPE ProtocolType);

USHORT RedirectCtxGetProxyPort(RC_PROTO_TYPE ProtocolType);
VOID RedirectCtxSetProxyPort(RC_PROTO_TYPE ProtocolType, USHORT Port);

#endif