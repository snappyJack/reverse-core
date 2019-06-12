#include "windows.h"
#include "stdio.h"

LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde) {
    g_pfWriteFile = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");//或取WriteFile的API地址（其实获取的是调试者的地址，但是没有影响）
    printf("g_pfWriteFile(%d)\n ", g_pfWriteFile);//g_pfWriteFile(1990541344)   76a54020
    memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
    ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
                      &g_chOrgByte, sizeof(BYTE), NULL);//g_cpdi.hProcess是被调试进程的句柄，g_pfWriteFile是WriteFile API的地址 ，此函数读取api第一个字节，存储到g_chOrgByte中
    WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
                       &g_chINT3, sizeof(BYTE), NULL);   //以上两个函数对调试进程进行读写，

    return TRUE;
}

BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde) {
    CONTEXT ctx;
    PBYTE lpBuffer = NULL;
    DWORD dwNumOfBytesToWrite, dwAddrOfBuffer, i;
    PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;

    if (EXCEPTION_BREAKPOINT == per->ExceptionCode) { //是断点异常时
        if (g_pfWriteFile == per->ExceptionAddress) {   //断点地址为writefile 的api地址时候
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,&g_chOrgByte, sizeof(BYTE), NULL);//恢复api第一个字节（unhook）

            ctx.ContextFlags = CONTEXT_CONTROL; //或取线程上下文
            GetThreadContext(g_cpdi.hThread, &ctx);

            ReadProcessMemory(g_cpdi.hProcess, (LPVOID) (ctx.Esp + 0x8),
                              &dwAddrOfBuffer, sizeof(DWORD), NULL);//或取api的第二个参数值
            ReadProcessMemory(g_cpdi.hProcess, (LPVOID) (ctx.Esp + 0xC),
                              &dwNumOfBytesToWrite, sizeof(DWORD), NULL);//或取api的第三个参数值

            lpBuffer = (PBYTE) malloc(dwNumOfBytesToWrite + 1);//分配临时缓冲区
            memset(lpBuffer, 0, dwNumOfBytesToWrite + 1);

            ReadProcessMemory(g_cpdi.hProcess, (LPVOID) dwAddrOfBuffer,
                              lpBuffer, dwNumOfBytesToWrite, NULL);//将第三个参数值复制到临时缓冲区
            printf("\n### original string ###\n%s\n", lpBuffer);

            for (i = 0; i < dwNumOfBytesToWrite; i++) {         //将小写字母转换为大写字母
                if (0x61 <= lpBuffer[i] && lpBuffer[i] <= 0x7A)
                    lpBuffer[i] -= 0x20;
            }

            printf("\n### converted string ###\n%s\n", lpBuffer);

            WriteProcessMemory(g_cpdi.hProcess, (LPVOID) dwAddrOfBuffer,
                               lpBuffer, dwNumOfBytesToWrite, NULL);//将变换后的缓冲区复制到writefile缓冲区

            free(lpBuffer);//释放临时缓冲区

            //将线程上下文的EIP更改为writefile首地址（当前为writefile（）+1位置，int3命令之后）
            ctx.Eip = (DWORD) g_pfWriteFile;
            SetThreadContext(g_cpdi.hThread, &ctx);

            // 运行被调试进程
            ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);//运行被调试进程
            Sleep(0);

            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
                               &g_chINT3, sizeof(BYTE), NULL);

            return TRUE;
        }
    }

    return FALSE;
}

void DebugLoop() {
    DEBUG_EVENT de;
    DWORD dwContinueStatus;
    while (WaitForDebugEvent(&de, INFINITE))//while循环等待被调试者发生事件，并根据不同的事件类型做出不同的反映
    {
        dwContinueStatus = DBG_CONTINUE;
        if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)// 被调试进程生成事件或者附加事件
        {
            OnCreateProcessDebugEvent(&de);
        } else if (EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode)// 异常事件
        {
            if (OnExceptionDebugEvent(&de))
                continue;
        } else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)// 被调试进程终止事件
        {
            break;//调试器终止
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);// 再次运行被调试者
    }
}

int main(int argc, char *argv[]) {
    DWORD dwPID;
    if (argc != 2)         //验证参数
    {
        printf("\nUSAGE : hookdbg.exe <pid>\n");
        return 1;
    }
    dwPID = atoi(argv[1]);      //pid
    if (!DebugActiveProcess(dwPID))        //将调试器（本运行文件）附加到运行的进程上，开始调试
    {
        printf("DebugActiveProcess(%d) failed!!!\n"
               "Error Code = %d\n", dwPID, GetLastError());
        return 1;
    }
    DebugLoop();// 调试循环，处理来自被调试者的调试事件
    return 0;
}
