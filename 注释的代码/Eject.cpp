// EjectDll.exe

#include "windows.h"
#include "tlhelp32.h"
#include "tchar.h"

#define DEF_PROC_NAME	(L"notepad.exe")
#define DEF_DLL_NAME	(L"myhack.dll")

DWORD FindProcessID(LPCTSTR szProcessName)
{
    DWORD dwPID = 0xFFFFFFFF;
    HANDLE hSnapShot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 pe;

    // 获取系统快照
    pe.dwSize = sizeof( PROCESSENTRY32 );
    hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPALL, NULL );

    // 查找进程
    Process32First(hSnapShot, &pe);
    do
    {
        if(!_tcsicmp(szProcessName, (LPCTSTR)pe.szExeFile))
        {
            dwPID = pe.th32ProcessID;
            break;
        }
    }
    while(Process32Next(hSnapShot, &pe));

    CloseHandle(hSnapShot);

    return dwPID;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    LUID luid;

    if( !OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken) )
    {
        _tprintf(L"OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    if( !LookupPrivilegeValue(NULL,           // lookup privilege on local system
                              lpszPrivilege,  // privilege to lookup
                              &luid) )        // receives LUID of privilege
    {
        _tprintf(L"LookupPrivilegeValue error: %u\n", GetLastError() );
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if( bEnablePrivilege )
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if( !AdjustTokenPrivileges(hToken,
                               FALSE,
                               &tp,
                               sizeof(TOKEN_PRIVILEGES),
                               (PTOKEN_PRIVILEGES) NULL,
                               (PDWORD) NULL) )
    {
        _tprintf(L"AdjustTokenPrivileges error: %u\n", GetLastError() );
        return FALSE;
    }

    if( GetLastError() == ERROR_NOT_ALL_ASSIGNED )
    {
        _tprintf(L"The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

BOOL EjectDll(DWORD dwPID, LPCTSTR szDllName)
{
    BOOL bMore = FALSE, bFound = FALSE;
    HANDLE hSnapshot, hProcess, hThread;
    HMODULE hModule = NULL;
    MODULEENTRY32 me = { sizeof(me) };
    LPTHREAD_START_ROUTINE pThreadProc;

    // dwPID = notepad 进程id
    // 使用TH32CS_SNAPMODULE 参数，获取加载到notepad 进程dll的名称
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);//句柄

    bMore = Module32First(hSnapshot, &me);
    for( ; bMore ; bMore = Module32Next(hSnapshot, &me) )//循环比较地址
    {
        if( !_tcsicmp((LPCTSTR)me.szModule, szDllName) ||
            !_tcsicmp((LPCTSTR)me.szExePath, szDllName) )
        {
            bFound = TRUE;
            break;
        }
    }

    if( !bFound )
    {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )//获取目标进程的句柄
    {
        _tprintf(L"OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
        return FALSE;
    }

    hModule = GetModuleHandle(L"kernel32.dll");
    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");//获取FreeLibrary的api地址
    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                 pThreadProc, me.modBaseAddr,
                                 0, NULL);      //卸载dll
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    CloseHandle(hSnapshot);

    return TRUE;
}

int _tmain(int argc, TCHAR* argv[])
{
    DWORD dwPID = 0xFFFFFFFF;

    // find process
    dwPID = FindProcessID(DEF_PROC_NAME);//查找notepad的id
    if( dwPID == 0xFFFFFFFF )
    {
        _tprintf(L"There is no <%s> process!\n", DEF_PROC_NAME);
        return 1;
    }

    _tprintf(L"PID of \"%s\" is %d\n", DEF_PROC_NAME, dwPID);

    // 改变权限
    if( !SetPrivilege(SE_DEBUG_NAME, TRUE) )
        return 1;

    // 卸载dll
    if( EjectDll(dwPID, DEF_DLL_NAME) )
        _tprintf(L"EjectDll(%d, \"%s\") success!!!\n", dwPID, DEF_DLL_NAME);
    else
        _tprintf(L"EjectDll(%d, \"%s\") failed!!!\n", dwPID, DEF_DLL_NAME);

    return 0;
}
