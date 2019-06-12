#include "stdio.h"
#include "wchar.h"
#include "windows.h"

typedef BOOL (WINAPI *PFSETWINDOWTEXTW)(HWND hWnd, LPWSTR lpString);

FARPROC g_pOrgFunc = NULL;//全局变量

BOOL WINAPI MySetWindowTextW(HWND hWnd, LPWSTR lpString)
{
    wchar_t* pNum = L"零一二三四五六七八九";
    wchar_t temp[2] = {0,};
    int i = 0, nLen = 0, nIndex = 0;
    nLen = wcslen(lpString);
    for(i = 0; i < nLen; i++)
    {
        if( L'0' <= lpString[i] && lpString[i] <= L'9' )//将阿拉伯数字转换为中文数字，lpString是宽字节版字符串
        {
            temp[0] = lpString[i];
            nIndex = _wtoi(temp);
            lpString[i] = pNum[nIndex];
        }
    }
    return ((PFSETWINDOWTEXTW)g_pOrgFunc)(hWnd, lpString);//调用user32API，lpString为修改后的内容
}

BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)//负责勾取IAT
{
	HMODULE hMod;
	LPCSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc; 
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwRVA;
	PBYTE pAddr;

	hMod = GetModuleHandle(NULL);//hMod = ImageBase
	pAddr = (PBYTE)hMod;//pAddr = ImageBase
	pAddr += *((DWORD*)&pAddr[0x3C]);// pAddr = VA to PE signature (IMAGE_NT_HEADERS)
	dwRVA = *((DWORD*)&pAddr[0x80]);// dwRVA = RVA to IMAGE_IMPORT_DESCRIPTOR Table
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod+dwRVA);// pImportDesc = VA to IMAGE_IMPORT_DESCRIPTOR Table

	for( ; pImportDesc->Name; pImportDesc++ )//循环遍历IDT
	{
		szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);// szLibName = VA to IMAGE_IMPORT_DESCRIPTOR.Name
		if( !_stricmp(szLibName, szDllName) )//比较user32.dll与szLibName
		{
            // pThunk = IMAGE_IMPORT_DESCRIPTOR.FirstThunk
            //        = VA to IAT(Import Address Table)
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);//pThunk就是user32的IAT

			for( ; pThunk->u1.Function; pThunk++ )// pThunk->u1.Function = VA to API 遍历IAT
			{
				if( pThunk->u1.Function == (DWORD)pfnOrg )//查找SetWindowTextW的地址
				{
					VirtualProtect((LPVOID)&pThunk->u1.Function,4,PAGE_EXECUTE_READWRITE,&dwOldProtect);//Win32 函数的逻辑包装函数
                    pThunk->u1.Function = (DWORD)pfnNew;//修改IAT的值
                    VirtualProtect((LPVOID)&pThunk->u1.Function,4,dwOldProtect,&dwOldProtect);
					return TRUE;
				}
			}
		}
	}	return FALSE;
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch( fdwReason )
	{		case DLL_PROCESS_ATTACH : 
           	g_pOrgFunc = GetProcAddress(GetModuleHandle(L"user32.dll"),"SetWindowTextW");//保存原始API地址
			hook_iat("user32.dll", g_pOrgFunc, (PROC)MySetWindowTextW);//使用hookiat!MySetWindowText()勾取user32的SetWindowTextW
			break;
		case DLL_PROCESS_DETACH :
            hook_iat("user32.dll", (PROC)MySetWindowTextW, g_pOrgFunc);//unhook，恢复calc的IAT原来的值
			break;
	}
	return TRUE;
}
