#pragma once
#include<windows.h>
#include <TlHelp32.h>
#include <stdio.h>

class HardBreakHook {
public:
	PVOID exceptionHandle = nullptr;   //异常处理函数                        
	uintptr_t dr0 = 0;
	uintptr_t dr1 = 0;                                        
	uintptr_t dr2 = 0;
	uintptr_t dr3 = 0;
	uintptr_t dr7 = 0;
	DWORD removeThread[0x20] = { 0 };                         
	PVECTORED_EXCEPTION_HANDLER exceptionHandleFunction = nullptr; 

	// 默认构造函数
	HardBreakHook() {}

	// 带参构造函数
	HardBreakHook(uintptr_t d0, uintptr_t d1, uintptr_t d2, uintptr_t d3, uintptr_t d7,
		PVECTORED_EXCEPTION_HANDLER exceptionHandleFunc, DWORD* remove)
		: dr0(d0), dr1(d1), dr2(d2), dr3(d3), dr7(d7), exceptionHandleFunction(exceptionHandleFunc) {
		memcpy(removeThread, remove, sizeof(remove));
		exceptionHandle = AddVectoredExceptionHandler(1, exceptionHandleFunction);//1被放置在异常处理链的前面
		hook();
	}

	// 检查线程是否已被挂钩
	BOOL isHookThread(DWORD threadId);

	// 设置异常处理函数
	void setExceptionHandlingFunction(PVECTORED_EXCEPTION_HANDLER func);

	// 安装Hook
	void hook();

	// 卸载Hook
	void unHook();
};
