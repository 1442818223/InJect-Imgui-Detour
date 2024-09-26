
#include "hardbreakhook.hpp"


HardBreakHook g_hbHook;

ULONG_PTR HookAddr = 0;

void OutputDebugInfo(const char* format, ...) {
	char debugMsg[256];
	va_list args;
	va_start(args, format);
	vsnprintf(debugMsg, sizeof(debugMsg), format, args);
	va_end(args);
	OutputDebugStringA(debugMsg);
}


LONG NTAPI exceptionHandle(struct _EXCEPTION_POINTERS* context) {

	//OutputDebugStringA("[db] 异常处理函数被调用\n");  //这个地方不能调用这个傻逼函数,会闪退*******

	// 判断是否是单步异常（硬件断点触发的异常）
	if (context->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		// 判断是否是我们设定的断点地址触发的异常
		if ((ULONG_PTR)context->ExceptionRecord->ExceptionAddress == HookAddr) {
			// 可以在这里任意处理我们希望的异常处理逻辑
			// ...
			// 
			//if (IsBadReadPtr((void*)异常信息->ContextRecord->Eax, sizeof(ULONG32))) {
			//	return EXCEPTION_CONTINUE_SEARCH;
			//}

			//写在里面的打印都不起作用************************************


			//Plants.exe+30A11 - 01 88 60550000        - add [eax+00005560],ecx
			//还原处理
			//1,把原来的逻辑写一下   因为我们只做了打印处理
			//2,跳过这句代码的长度
			// 
			// 还原原始指令: add [eax+00005560],ecx
			*(ULONG32*)(context->ContextRecord->Eax + 0x5560) += (context->ContextRecord->Ecx + 1000);
			context->ContextRecord->Eip += 6;


			//异常信息->ContextRecord->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

			// 是我们的异常，处理完毕后继续运行
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	// 如果不是我们要处理的异常，交由系统或其他处理程序处理
	return EXCEPTION_CONTINUE_SEARCH;
}

void 初始化()
{

	//Plants.exe + 30A11 - 01 88 60550000 - add[eax + 00005560], ecx

	ULONG_PTR 模块句柄 = (ULONG32)GetModuleHandle(L"Plants.exe");
	HookAddr = 模块句柄 + 0x30A11;
	

	char debugMsg[256];
	snprintf(debugMsg, sizeof(debugMsg), "[db] 模块句柄: 0x%08X, HookAddr: 0x%08X", 模块句柄, HookAddr);
	OutputDebugStringA(debugMsg);

	g_hbHook.dr0 = HookAddr;
	//g_hbHook.dr7=  0x55;
	g_hbHook.dr7 = 0x1;


	g_hbHook.removeThread[0] = GetCurrentThreadId();//排除本线程
	g_hbHook.setExceptionHandlingFunction(exceptionHandle);
	g_hbHook.hook();


	///g_hbHook.unHook();
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		//CloseHandle(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)初始化, NULL, 0, NULL));
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)初始化, NULL, 0, NULL);

		//初始化();
		break;

	case DLL_THREAD_ATTACH:// // 对每一个新创建的线程均添加硬件断点
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

