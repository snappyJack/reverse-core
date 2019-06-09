// CodeInjection.cpp
// reversecore@gmail.com
// http://www.reversecore.com

#include "windows.h"
#include "stdio.h"

typedef struct _THREAD_PARAM
{
    FARPROC pFunc[2];               // LoadLibraryA(), GetProcAddress()
    char    szBuf[4][128];          // "user32.dll", "MessageBoxA", "www.reversecore.com", "ReverseCore"
} THREAD_PARAM, *PTHREAD_PARAM;

typedef HMODULE (WINAPI *PFLOADLIBRARYA)
        (
                LPCSTR lpLibFileName
        );

typedef FARPROC (WINAPI *PFGETPROCADDRESS)
        (
                HMODULE hModule,
                LPCSTR lpProcName
        );

typedef int (WINAPI *PFMESSAGEBOXA)
        (
                HWND hWnd,
                LPCSTR lpText,
                LPCSTR lpCaption,
                UINT uType
        );

DWORD WINAPI ThreadProc(LPVOID lParam)//哦哦！！注入的代码是这些！！！！！
{
    PTHREAD_PARAM   pParam      = (PTHREAD_PARAM)lParam;
    HMODULE         hMod        = NULL;
    FARPROC         pFunc       = NULL;

    // LoadLibrary()
    hMod = ((PFLOADLIBRARYA)pParam->pFunc[0])(pParam->szBuf[0]);    // "user32.dll"句柄
    if( !hMod )
        return 1;

    // GetProcAddress()
    pFunc = (FARPROC)((PFGETPROCADDRESS)pParam->pFunc[1])(hMod, pParam->szBuf[1]);  // "MessageBoxA"地址
    if( !pFunc )
        return 1;

    // MessageBoxA()
    ((PFMESSAGEBOXA)pFunc)(NULL, pParam->szBuf[2], pParam->szBuf[3], MB_OK);//运行messageboxa函数（后边两个是参数）

    return 0;
}

BOOL InjectCode(DWORD dwPID)
{
    HMODULE         hMod            = NULL;
    THREAD_PARAM    param           = {0,};
    HANDLE          hProcess        = NULL;
    HANDLE          hThread         = NULL;
    LPVOID          pRemoteBuf[2]   = {0,};
    DWORD           dwSize          = 0;

    hMod = GetModuleHandleA("kernel32.dll");//获取本进程中kernel32.dll句柄

    // set THREAD_PARAM
    param.pFunc[0] = GetProcAddress(hMod, "LoadLibraryA");//或取本进程LoadLibraryA函数地址       函数地址
    param.pFunc[1] = GetProcAddress(hMod, "GetProcAddress");//获取本进程GetProcAddress函数地址       函数地址
    strcpy_s(param.szBuf[0], "user32.dll");//复制字符串              字符串地址
    strcpy_s(param.szBuf[1], "MessageBoxA");//复制字符串             字符串地址
    strcpy_s(param.szBuf[2], "www.reversecore.com");//复制字符串     字符串地址
    strcpy_s(param.szBuf[3], "ReverseCore");//复制字符串             字符串地址

    // 打开进程
    if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS,   // dwDesiredAccess
                                  FALSE,                // bInheritHandle
                                  dwPID)) )             // dwProcessId
    {
        printf("OpenProcess() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    // 为data分配内存，
    dwSize = sizeof(THREAD_PARAM);
    if( !(pRemoteBuf[0] = VirtualAllocEx(hProcess,          // hProcess
                                         NULL,                 // lpAddress
                                         dwSize,               // dwSize
                                         MEM_COMMIT,           // flAllocationType
                                         PAGE_READWRITE)) )    // flProtect
    {
        printf("VirtualAllocEx() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }
    //将data注入到分配的内存中
    if( !WriteProcessMemory(hProcess,                       // hProcess
                            pRemoteBuf[0],                  // lpBaseAddress
                            (LPVOID)&param,                 // lpBuffer
                            dwSize,                         // nSize
                            NULL) )                         // [out] lpNumberOfBytesWritten
    {
        printf("WriteProcessMemory() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    // 为code分配内存
    dwSize = (DWORD)InjectCode - (DWORD)ThreadProc;
    if( !(pRemoteBuf[1] = VirtualAllocEx(hProcess,          // hProcess
                                         NULL,                 // lpAddress
                                         dwSize,               // dwSize
                                         MEM_COMMIT,           // flAllocationType
                                         PAGE_EXECUTE_READWRITE)) )    // flProtect
    {
        printf("VirtualAllocEx() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }
    //将code注入到内存中
    if( !WriteProcessMemory(hProcess,                       // hProcess
                            pRemoteBuf[1],                  // lpBaseAddress
                            (LPVOID)ThreadProc,             // lpBuffer
                            dwSize,                         // nSize
                            NULL) )                         // [out] lpNumberOfBytesWritten
    {
        printf("WriteProcessMemory() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }
    //执行远程线程
    if( !(hThread = CreateRemoteThread(hProcess,            // hProcess
                                       NULL,                // lpThreadAttributes
                                       0,                   // dwStackSize
                                       (LPTHREAD_START_ROUTINE)pRemoteBuf[1],     // 注入线程的代码地址
                                       pRemoteBuf[0],       // lpParameter       //注入线程的数据地址
                                       0,                   // dwCreationFlags
                                       NULL)) )             // lpThreadId
    {
        printf("CreateRemoteThread() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
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
        printf("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    if( !LookupPrivilegeValue(NULL,           // lookup privilege on local system
                              lpszPrivilege,  // privilege to lookup
                              &luid) )        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError() );
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
        printf("AdjustTokenPrivileges error: %u\n", GetLastError() );
        return FALSE;
    }

    if( GetLastError() == ERROR_NOT_ALL_ASSIGNED )
    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

int main(int argc, char *argv[])
{
    DWORD dwPID     = 0;

    if( argc != 2 )//验证参数
    {
        printf("\n USAGE  : %s <pid>\n", argv[0]);
        return 1;
    }

    // 改变权限
    if( !SetPrivilege(SE_DEBUG_NAME, TRUE) )
        return 1;

    // 代码注入
    dwPID = (DWORD)atol(argv[1]);
    InjectCode(dwPID);

    return 0;
}
