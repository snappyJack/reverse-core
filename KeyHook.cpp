#include "stdio.h"
#include "windows.h"

#define DEF_PROCESS_NAME		"notepad.exe"

HINSTANCE g_hInstance = NULL;	//dll文件句柄
HHOOK g_hHook = NULL;
HWND g_hWnd = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)//hinstDLL：268435456  
{
	//printf("mortyhinstDLL(%d)\n ", hinstDLL);
	//printf("mortydwReason(%d)\n ", dwReason);
	//printf("mortylpvReserved(%d)\n ", lpvReserved);
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH://1  当这个DLL被映射到了进程的地址空间时
		g_hInstance = hinstDLL;
		break;

	case DLL_PROCESS_DETACH://0	这个DLL从进程的地址空间中解除映射
		break;
	}

	return TRUE;
}
// 键盘过程
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)//wParam为键盘的虚拟键
{
	char szPath[MAX_PATH] = { 0, };
	char *p = NULL;

	if (nCode >= 0)
	{
		// bit 31 : 0 => press, 1 => release
		if (!(lParam & 0x80000000))
		{
			GetModuleFileNameA(NULL, szPath, MAX_PATH);
			p = strrchr(szPath, '\\');

			// 比较当前进程名称，若为notepad，则消息不会传递给应用程序
			if (!_stricmp(p + 1, DEF_PROCESS_NAME))
				return 1;
		}
	}

	// 若非notepad，则传给下一个程序
	return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}


//如果这是一段cpp的代码，那么加入extern"C"{和}处理其中的代码。
#ifdef __cplusplus
extern "C" {
#endif
	__declspec(dllexport) void HookStart()//这个函数要从本DLL导出。我要给别人用。
	{
		g_hHook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, g_hInstance, 0);
	}

	__declspec(dllexport) void HookStop()//这个函数要从本DLL导出。我要给别人用。
	{
		if (g_hHook)
		{
			UnhookWindowsHookEx(g_hHook);
			g_hHook = NULL;
		}
	}
#ifdef __cplusplus
}
#endif
