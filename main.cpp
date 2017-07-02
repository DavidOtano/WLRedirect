#include <WinSock2.h>
#include <Windows.h>

typedef int (WINAPI* LPCONNECT)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI* LPSEND)(SOCKET, const char*, int, int);
typedef u_short (WINAPI* LPNTOHS)(u_short);
typedef u_short (WINAPI* LPHTONS)(u_short);
typedef int (WINAPI* LPIOCTLSOCKET)(SOCKET, long, u_long*);
typedef hostent* (WINAPI* LPGETHOSTBYNAME)(const char*);
typedef int (WINAPI* LPWSAGETLASTERROR)(void);
typedef int (WINAPI* LPSELECT)(int, fd_set FAR*, fd_set FAR*, 
			fd_set FAR*, const struct timeval FAR*);
typedef int (WINAPI* LP__WSAFDISSET)(SOCKET, fd_set FAR*);
typedef SOCKET (WINAPI* LPSOCKET)(int, int, int);

DWORD HookProc(DWORD HookFunc, DWORD MyFunc, DWORD OrigFunc);
int WINAPI __connect(SOCKET s, const struct sockaddr* name, int namelen);
bool FixedSend(SOCKET s, char* buf, int len) ;

LPCONNECT g_pConnect = NULL;
LPSEND g_psend = NULL;
LPNTOHS g_pntohs = NULL;
LPHTONS g_phtons = NULL;
LPIOCTLSOCKET g_pioctlsocket = NULL;
LPGETHOSTBYNAME g_pgethostbyname = NULL;
LPWSAGETLASTERROR g_pWSAGetLastError = NULL;
LPSELECT g_pselect = NULL;
LP__WSAFDISSET g_p__WSAFDIsSet = NULL;
LPSOCKET g_psocket = NULL;

BOOL APIENTRY DllMain(
	HINSTANCE hInstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved
	)
{
	switch(fdwReason) {
	case DLL_PROCESS_ATTACH:
		g_psend = (LPSEND)GetProcAddress(GetModuleHandle("WS2_32.DLL"), "send");
		g_pntohs = (LPNTOHS)GetProcAddress(GetModuleHandle("WS2_32.DLL"), "ntohs");
		g_phtons = (LPHTONS)GetProcAddress(GetModuleHandle("WS2_32.DLL"), "htons");
		g_pioctlsocket = (LPIOCTLSOCKET)GetProcAddress(GetModuleHandle("WS2_32.DLL"), "ioctlsocket");
		g_pgethostbyname = (LPGETHOSTBYNAME)GetProcAddress(GetModuleHandle("WS2_32.DLL"), "gethostbyname");
		g_pWSAGetLastError = (LPWSAGETLASTERROR)GetProcAddress(GetModuleHandle("WS2_32.DLL"), "WSAGetLastError");
		g_pselect = (LPSELECT)GetProcAddress(GetModuleHandle("WS2_32.DLL"), "select");
		g_p__WSAFDIsSet = (LP__WSAFDISSET)GetProcAddress(GetModuleHandle("WS2_32.DLL"), "__WSAFDIsSet");
		g_psocket = (LPSOCKET)GetProcAddress(GetModuleHandle("WS2_32.DLL"), "socket");
		g_pConnect = (LPCONNECT)HookProc((DWORD)GetProcAddress(GetModuleHandle("WS2_32.DLL"), "connect"), (DWORD)__connect, (DWORD)g_pConnect);
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


DWORD HookProc(DWORD HookFunc, DWORD MyFunc, DWORD OrigFunc)
{
	unsigned char NewData[5], DetourJump[5], OldData[5];
	DWORD OldProtect;
	int i;
	unsigned char* HookFuncPtr = (unsigned char*) HookFunc;
	unsigned char* HookDetour = (unsigned char*)new char[(25)];
	for(i = 0; i < 25; i++)
		HookDetour[i] = 0x90; //NOP
	NewData[0] = 0xE9; //JMP (near)
	*(PDWORD)&NewData[1] = (DWORD)((DWORD)MyFunc - ((DWORD)HookFunc + 5));
	DetourJump[0] = 0xE9;
	*(PDWORD)&DetourJump[1] = (DWORD)((DWORD)HookFunc - ((DWORD)HookDetour + 14 + 5));
	VirtualProtectEx(GetCurrentProcess(), (void*)HookFunc, 10, PAGE_EXECUTE_WRITECOPY, &OldProtect);
	for(i = 0; i < 5; i++)
	{
		OldData[i] = HookFuncPtr[i];
		HookFuncPtr[i] = NewData[i];
	}
	VirtualProtectEx(GetCurrentProcess(), (void*)HookFunc, 10, OldProtect, NULL);
	VirtualProtectEx(GetCurrentProcess(), (void*)HookDetour, 25, PAGE_EXECUTE_WRITECOPY, &OldProtect);
	for(i = 0; i < 5; i++)
		HookDetour[i] = OldData[i];
	HookDetour[24-5] = DetourJump[0];
	HookDetour[24-4] = DetourJump[1];
	HookDetour[24-3] = DetourJump[2];
	HookDetour[24-2] = DetourJump[3];
	HookDetour[24-1] = DetourJump[4];
	HookDetour[24] = 0xC3; //RET
	VirtualProtectEx(GetCurrentProcess(), (void*)HookDetour, 25, OldProtect, NULL);
	OrigFunc = (DWORD)HookDetour;
	return OrigFunc;
}

int WINAPI __connect(SOCKET s, const struct sockaddr* name, int namelen)
{
	int nRet = SOCKET_ERROR;
	u_long nArg = 0;
	hostent* pent;
	int ntries = 0;
	SOCKADDR_IN sin;
	fd_set fds;
	int sel;
	bool isset = false;
	DWORD dwTick;
	if(g_pntohs(((SOCKADDR_IN*)name)->sin_port) == 6414) {
		if(NULL != FindWindow(NULL, "Wonderland Proxy")) {
			do {
				pent = g_pgethostbyname("localhost");
			} while(!pent && ++ntries < 5);

			if(NULL != pent) {
				sin.sin_addr.S_un.S_addr = *(DWORD*)(pent->h_addr_list[0]);
				sin.sin_family = AF_INET;
				sin.sin_port = g_phtons(6414);

				nRet = g_pConnect(s, (struct sockaddr*)&sin, sizeof(SOCKADDR_IN));

				dwTick = GetTickCount();
				do {
					FD_ZERO(&fds);
					FD_SET(s, &fds);
					timeval tv = {0};
					tv.tv_sec = 1;
					sel = g_pselect(s+1, NULL, &fds, NULL, &tv);
					isset = (g_p__WSAFDIsSet(s, &fds))? true : false;
				} while(sel != SOCKET_ERROR && !isset && (dwTick - GetTickCount()) < 1000);

				if(sel != SOCKET_ERROR) {
					if(!FixedSend(s, (char*)name, sizeof(SOCKADDR_IN))) {
						nRet = SOCKET_ERROR;
					} else nRet = 0;
				}
			}
		} else nRet = g_pConnect(s, name, namelen);
	} else nRet = g_pConnect(s, name, namelen);


	return nRet;
}

bool FixedSend(SOCKET s, char* buf, int len) {
	int ref		,
		out = 0	;
	bool ret = true;
	do {
		ref = g_psend(s, buf+out, len-out, 0);
		if(ref == SOCKET_ERROR) {
			ref = g_pWSAGetLastError();
			if(ref != WSAEWOULDBLOCK) {
				ret = false;
				break;
			}
		} else if(ref == 0) {
			ret = false;
			break;
		} else out += ref;
	} while(out < len);

	return ret;
}

