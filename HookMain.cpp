#include "stdio.h"
#include "conio.h"
#include "windows.h"

#define	DEF_DLL_NAME		"KeyHook.dll"
#define	DEF_HOOKSTART		"HookStart"
#define	DEF_HOOKSTOP		"HookStop"

typedef void (*PFN_HOOKSTART)();
typedef void (*PFN_HOOKSTOP)();

void main()
{
	HMODULE			hDll = NULL;
	PFN_HOOKSTART	HookStart = NULL;
	PFN_HOOKSTOP	HookStop = NULL;
	char			ch = 0;

    // 加载KeyHook.dll  HMODULE —— Handle to a module. 
	hDll = LoadLibraryA("KeyHook.dll");
    if( hDll == NULL )
    {
        printf("LoadLibrary(%s) failed!!! [%d]", DEF_DLL_NAME, GetLastError());
        return;
    }
	printf("hDll(%d)\n ", hDll);
    // 获取导出函数地址
	HookStart = (PFN_HOOKSTART)GetProcAddress(hDll, DEF_HOOKSTART);
	printf("HookStart(%d)\n ", HookStart);
	HookStop = (PFN_HOOKSTOP)GetProcAddress(hDll, DEF_HOOKSTOP);
	printf("HookStop(%d)\n ", HookStop);
    // 开始勾取
	HookStart();

    // 等待直到用户输入q
	printf("mortypress 'a' to quit!\n");
	while( _getch() != 'a' )	;

    // 停止勾取
	HookStop();
	
    // 卸载KeyHook.dll
	FreeLibrary(hDll);
}
