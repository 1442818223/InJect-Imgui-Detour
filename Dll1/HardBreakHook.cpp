#include "hardbreakhook.hpp"

// 检查线程是否已被挂钩
BOOL HardBreakHook::isHookThread(DWORD threadId)
{
	for (DWORD i = 0; i < 0x20; ++i) {
		if (removeThread[i] == threadId) {
			return  FALSE;   // 线程已被挂钩
		}
	}
	return TRUE;  // 线程未被挂钩
}

// 设置异常处理函数
void  HardBreakHook::setExceptionHandlingFunction(PVECTORED_EXCEPTION_HANDLER func)
{
	//exceptionHandle = AddVectoredContinueHandler(1,func);
	exceptionHandle = AddVectoredExceptionHandler(1, func);
}

// 安装Hook
void  HardBreakHook::hook()
{
	// 创建快照句柄，获取当前系统中所有线程的快照
	HANDLE 快照句柄 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (快照句柄 != INVALID_HANDLE_VALUE) {
		THREADENTRY32 thread_entry32;
		thread_entry32.dwSize = sizeof(thread_entry32);
		HANDLE 线程句柄 = NULL;

		// 遍历所有线程
		if (Thread32First(快照句柄, &thread_entry32)) {
			do {
				// 判断线程所属的进程ID是否等于当前进程ID
				if (thread_entry32.th32OwnerProcessID == GetCurrentProcessId()) {
					// 判断是否是我们要hook的线程
					if (isHookThread(thread_entry32.th32ThreadID)) { //理论除了自己上每个线程都插了
						// 获得线程句柄
						线程句柄 = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_entry32.th32ThreadID);
						if (线程句柄) {
							// 暂停线程
							SuspendThread(线程句柄);

							// 开始hook
							CONTEXT context;
							context.ContextFlags = CONTEXT_ALL;
							GetThreadContext(线程句柄, &context);

							// 设置硬件断点寄存器 ,对每一条已存在的线程设置硬件断点
							context.Dr0 = dr0;
							context.Dr1 = dr1;
							context.Dr2 = dr2;
							context.Dr3 = dr3;
							context.Dr7 = dr7;

							// 设置线程上下文
							SetThreadContext(线程句柄, &context);

							// 恢复线程
							ResumeThread(线程句柄);

							// 关闭句柄
							CloseHandle(线程句柄);
						}
					}
				}
			} while (Thread32Next(快照句柄, &thread_entry32));
		}

		// 关闭快照句柄
		CloseHandle(快照句柄);
	}
}

// 卸载Hook
void  HardBreakHook::unHook()
{
	// 清空硬件断点寄存器
	dr0 = 0;
	dr1 = 0;
	dr2 = 0;
	dr3 = 0;
	dr7 = 0;

	// 调用hook函数，将清空后的寄存器值应用到目标线程
	hook();

	RemoveVectoredContinueHandler(exceptionHandle);
}
