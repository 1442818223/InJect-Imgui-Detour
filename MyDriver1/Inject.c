#include "Inject.h"
#include "Memory.h"
#include "MemLoadDll.h"
#include <ntimage.h>

typedef NTSTATUS(NTAPI *_ZwCreateThreadEx)(   //创建线程
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID StartContext,
	IN ULONG CreateThreadFlags,
	IN SIZE_T ZeroBits OPTIONAL,
	IN SIZE_T StackSize OPTIONAL,
	IN SIZE_T MaximumStackSize OPTIONAL,
	IN PVOID AttributeList
	);

EXTERN_C PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);////拿exe模块基址

ULONG GetStartAddressOffset()
{
	static ULONG offset = 0;
	if (offset) return offset;

	UNICODE_STRING funcName = {0};
	RtlInitUnicodeString(&funcName, L"PsGetThreadId");
	PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
	ULONG tidOffset = 0;

	for (int i = 0; i < 100; i++)
	{
		if (func[i] == 0xc3 && (func[i + 1] == 0xcc || func[i + 1] == 0x90) && (func[i + 2] == 0xcc || func[i + 2] == 0x90))
		{
			tidOffset = *(PULONG)(func + i - 4);  //拿到存放cid的位置
			break;
		}
	}

	if (!tidOffset) return 0;

	offset = tidOffset - 0x30;

	
	return offset;
}

ULONG GetWin32StartAddressOffset()
{
	static ULONG offset = 0;
	if (offset) return offset;
	RTL_OSVERSIONINFOW version;
	RtlGetVersion(&version);

	UNICODE_STRING funcName = { 0 };
	RtlInitUnicodeString(&funcName, L"PsGetThreadId");
	PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
	ULONG tidOffset = 0;

	for (int i = 0; i < 100; i++)
	{//定位到末尾再往前减4
		if (func[i] == 0xc3 && (func[i + 1] == 0xcc || func[i + 1] == 0x90) && (func[i + 2] == 0xcc || func[i + 2] == 0x90))
		{
			tidOffset = *(PULONG)(func +i - 4);
			break;
		}
	}

	if (!tidOffset) return 0;


	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
	{
		offset = tidOffset + 0x58;
	}
	else
	{
		offset = tidOffset + 0x50;
	}

	return offset;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PULONG GetPspNotifyEnableMask()
{
	static PULONG address = 0;
	if (address) return address;


	UNICODE_STRING funcName = { 0 };
	RtlInitUnicodeString(&funcName, L"PsSetLoadImageNotifyRoutineEx");    
	PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
	if (!func)
	{
		RtlInitUnicodeString(&funcName, L"PsSetLoadImageNotifyRoutine");//没有Ex的就拿这个 
		func = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
	}

	LONG Offset = 0;

	for (int i = 0; i < 100; i++)
	{
		
		if (func[i] == 0xF0      
			&& func[i + 1] == 0x0F
			&& func[i + 2] == 0xBA
			&& func[i + 3] == 0x2D
			)
		{
			Offset = *(PULONG)(func + i + 4);
			ULONG64 next = (ULONG64)(func + i+ 9);
			address = (PULONG)(next + Offset);
			break;
		}
	}

	return address;
}

ULONG PatchNotificationMask(PULONG NotifyEnableMask)
{
	if (MmIsAddressValid(NotifyEnableMask))
	{
		ULONG oldValue = *NotifyEnableMask;             //通知用的同一个Mask
		*NotifyEnableMask = 0;
		return oldValue;
	}

	return 0;
}

VOID RePatchNotificationMask(PULONG NotifyEnableMask,ULONG oldValue)
{
	if (MmIsAddressValid(NotifyEnableMask))
	{
		*NotifyEnableMask = oldValue;
		
	}

	
}
///////////////////////////////////////////////////////////////////////////////////////////////////

ULONG GetEThreadListOffset()
{
	static ULONG offset = 0;
	if (offset) return offset;
	RTL_OSVERSIONINFOW version;
	RtlGetVersion(&version);

	UNICODE_STRING funcName = { 0 };
	RtlInitUnicodeString(&funcName, L"PsGetThreadId");
	PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
	ULONG tidOffset = 0;

	for (int i = 0; i < 100; i++)
	{
		if (func[i] == 0xc3 && (func[i + 1] == 0xcc || func[i + 1] == 0x90) && (func[i + 2] == 0xcc || func[i + 2] == 0x90))
		{
			tidOffset = *(PULONG)(func + i - 4);
			break;
		}
	}

	if (!tidOffset) return 0;


	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601 || version.dwBuildNumber >= 16299/* 1709 以上*/)
	{
		offset = tidOffset + 0x68;
	}
	else
	{
		offset = tidOffset + 0x60;
	}

	return offset;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
_ZwCreateThreadEx GetCreateThreadExFunc() //创建线程
{

	static ULONG64 findFunc = NULL;
	if (findFunc) return (_ZwCreateThreadEx)findFunc;
	UNICODE_STRING unName = { 0 };
	RtlInitUnicodeString(&unName, L"ZwCreateSymbolicLinkObject");
	PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&unName);
	func += 5;   //先用ida找到CreateThreadEx上面的导出函数加每个函数前面一样的5字节在往后找

	for (int i = 0; i < 0x30; i++)
	{
		if (func[i] == 0x48 && func[i + 1] == 0x8b && func[i + 2] == 0xc4)//函数头
		{
			findFunc = (ULONG64)(func + i);
			break;
		}
	}


	if (!findFunc) return NULL;

	KdPrint(("GetZwCreateThreadExAddr %llx\r\n", findFunc));
	return (_ZwCreateThreadEx)findFunc;
}

BOOLEAN CreateRemoteThreadByProcess(HANDLE pid, IN PVOID Address, IN ULONG64 Arg, PETHREAD * pthread)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	KAPC_STATE Kpc = { 0, };
	PEPROCESS eprocess = NULL;
	ULONG64 ReginSize = 8;
	HANDLE hThread = NULL;

	_ZwCreateThreadEx threadFunc = GetCreateThreadExFunc();

	if (threadFunc == NULL)
	{
		KdPrintEx((77, 0, "没有获取到线程函数ZwCreateThreadEx %X\r\n", Status));
		return FALSE;
	}



	Status = PsLookupProcessByProcessId(pid, &eprocess);

	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	ObDereferenceObject(eprocess);


	KeStackAttachProcess(eprocess, &Kpc);

	do
	{
		Status = threadFunc(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Address, Arg, 0, 0, 0x100000, 0x200000, NULL);
		if (!NT_SUCCESS(Status))
		{
			KdPrintEx((77, 0, "创建线程失败 %X\r\n", Status));
			break;
		}

		if (hThread)
		{
			ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, pthread, NULL);
			ZwClose(hThread);
		}

	} while (0);

	KeUnstackDetachProcess(&Kpc);

	return TRUE;
}



NTSTATUS InjectX64(HANDLE pid, char * shellcode, SIZE_T shellcodeSize)
{
	PEPROCESS Process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);
	KAPC_STATE kApcState = {0};

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);
		return NULL;
	}

	PUCHAR kfileDll = ExAllocatePool(PagedPool, shellcodeSize);
	memcpy(kfileDll, shellcode, shellcodeSize); //拿进来复制一次 因为不要破坏原来的内容

	BOOLEAN isuFileAllocatedll = FALSE;
	BOOLEAN isuShellcode = FALSE;
	BOOLEAN isuimageDll = FALSE;

	PUCHAR ufileDll = NULL;
	PUCHAR uShellcode = NULL;
	SIZE_T uShellcodeSize = 0;
	PUCHAR uImage = NULL;
	SIZE_T uImageSize = 0;

	KeStackAttachProcess(Process, &kApcState);
	do 
	{
		ufileDll = AllocateMemoryNotExecute(pid, shellcodeSize);

		if (!ufileDll)
		{
			break;
		}
		
		memcpy(ufileDll, kfileDll, shellcodeSize); //放进exe还要复制一次

		isuFileAllocatedll = TRUE;

		uShellcode = AllocateMemory(pid, sizeof(MemLoadShellcode_x64)); //申请解析PE内容的空间

		if (!uShellcode)
		{
			break;
		}

		isuShellcode = TRUE;

		memcpy(uShellcode, MemLoadShellcode_x64, sizeof(MemLoadShellcode_x64));//复制进内存

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ufileDll;
		PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(ufileDll + pDos->e_lfanew);
		uImageSize = pNts->OptionalHeader.SizeOfImage; //拿PE到内存中展开的大小

		uImage = AllocateMemory(pid, uImageSize);

		if (!uImage)
		{
			break;
		}

		uShellcode[0x50f] = 0x90;
		uShellcode[0x510] = 0x48;
		uShellcode[0x511] = 0xb8;
		*(PULONG64)&uShellcode[0x512] = (ULONG64)uImage;//将火绒修复的空间换成我们申请的空间

		PULONG mask = GetPspNotifyEnableMask(); 
		ULONG maskoldvalue = PatchNotificationMask(mask);//屏蔽回调

		PETHREAD thread = NULL;
		if (CreateRemoteThreadByProcess(pid, uShellcode, ufileDll, &thread))//让MemLoadShellcode_x64跑起来
		{
			ULONG StartAddressOffset = GetStartAddressOffset();             //得到_ETHREAD里面的StartAddress的Offset
			ULONG Win32StartAddressOffset = GetWin32StartAddressOffset();       //得到_ETHREAD里面的Win32StartAddress的Offset

			ULONG elistOffset = GetEThreadListOffset();//得到_ETHREAD里面的线程链表Offset

			ULONG64 exeAddress = (ULONG64)PsGetProcessSectionBaseAddress(Process);//拿exe模块基址

			*(PULONG64)((PUCHAR)thread + StartAddressOffset) = exeAddress + 0x1000; //+0x1000到对方模块的里面了,加多少无所谓
			*(PULONG64)((PUCHAR)thread + Win32StartAddressOffset) = exeAddress + 0x1000;
		
			PLIST_ENTRY elist = ((PUCHAR)thread + elistOffset);  //拿到线程链表
			RemoveEntryList(elist);
			InitializeListHead(elist);//移除完后必须初始化一下 否则有几率蓝屏
			
			KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);
			ObDereferenceObject(thread);
			memset(uImage, 0, PAGE_SIZE); //清空pe头
		}
		else 
		{
			isuimageDll = TRUE;
		}

		RePatchNotificationMask(mask, maskoldvalue);
	} while (0);


	if (isuFileAllocatedll)
	{
		FreeMemory(pid, ufileDll, shellcodeSize);
	}

	if (isuShellcode)
	{
		FreeMemory(pid, uShellcode, uShellcodeSize);
	}

	if (isuimageDll)
	{
		FreeMemory(pid, uImage, uImageSize);
	}

	KeUnstackDetachProcess(&kApcState);

	ExFreePool(kfileDll);

	return status;
}

NTSTATUS InjectX86(HANDLE pid, char *shellcode, SIZE_T shellcodeSize)
{
	PEPROCESS Process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);
	KAPC_STATE kApcState = { 0 };

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);
		return NULL;
	}

	PUCHAR kfileDll = ExAllocatePool(PagedPool, shellcodeSize);
	memcpy(kfileDll, shellcode, shellcodeSize); //拿进来复制一次 因为不要破坏原来的内容

	BOOLEAN isuFileAllocatedll = FALSE;
	BOOLEAN isuShellcode = FALSE;
	BOOLEAN isuimageDll = FALSE;

	PUCHAR ufileDll = NULL;
	PUCHAR uShellcode = NULL;
	SIZE_T uShellcodeSize = 0;
	PUCHAR uImage = NULL;
	SIZE_T uImageSize = 0;

	KeStackAttachProcess(Process, &kApcState);
	do
	{
		ufileDll = AllocateMemoryNotExecute(pid, shellcodeSize);

		if (!ufileDll)
		{
			break;
		}

		memcpy(ufileDll, kfileDll, shellcodeSize); //放进exe还要复制一次

		isuFileAllocatedll = TRUE;

		uShellcode = AllocateMemory(pid, sizeof(MemLoadShellcode_x86)); //申请解析PE内容的空间

		if (!uShellcode)
		{
			break;
		}

		isuShellcode = TRUE;

		memcpy(uShellcode, MemLoadShellcode_x86, sizeof(MemLoadShellcode_x86));//复制进内存

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ufileDll;
		PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(ufileDll + pDos->e_lfanew);
		uImageSize = pNts->OptionalHeader.SizeOfImage; //拿PE到内存中展开的大小

		uImage = AllocateMemory(pid, uImageSize);

		if (!uImage)
		{
			break;
		}
		//a00000    a5e7e0  
		//uShellcode[0x50f] = 0x90;
		//uShellcode[0x510] = 0x48;
		//uShellcode[0x511] = 0xb8;
		//*(PULONG64)&uShellcode[0x512] = (ULONG64)uImage;//将火绒修复的空间换成我们申请的空间

		PULONG mask = GetPspNotifyEnableMask();
		ULONG maskoldvalue = PatchNotificationMask(mask);//屏蔽回调


	
		PETHREAD thread = NULL;
		if (CreateRemoteThreadByProcess(pid, uShellcode, ufileDll, &thread))//让MemLoadShellcode_x86跑起来
		{
			ULONG StartAddressOffset = GetStartAddressOffset();             //得到_ETHREAD里面的StartAddress的Offset
			ULONG Win32StartAddressOffset = GetWin32StartAddressOffset();       //得到_ETHREAD里面的Win32StartAddress的Offset

			ULONG elistOffset = GetEThreadListOffset();//得到_ETHREAD里面的线程链表Offset

			ULONG64 exeAddress = (ULONG64)PsGetProcessSectionBaseAddress(Process);//拿exe模块基址

			*(PULONG64)((PUCHAR)thread + StartAddressOffset) = exeAddress + 0x1000; //+0x1000到对方模块的里面了,加多少无所谓
			*(PULONG64)((PUCHAR)thread + Win32StartAddressOffset) = exeAddress + 0x1000;

			PLIST_ENTRY elist = ((PUCHAR)thread + elistOffset);  //拿到线程链表
			RemoveEntryList(elist);
			InitializeListHead(elist);//移除完后必须初始化一下 否则有几率蓝屏

			KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);
			ObDereferenceObject(thread);
			memset(uImage, 0, PAGE_SIZE); //清空pe头
		}
		else
		{
			isuimageDll = TRUE;
		}

		RePatchNotificationMask(mask, maskoldvalue);
	} while (0);


	if (isuFileAllocatedll)
	{
		FreeMemory(pid, ufileDll, shellcodeSize);
	}

	if (isuShellcode)
	{
		FreeMemory(pid, uShellcode, uShellcodeSize);
	}

	if (isuimageDll)
	{
		FreeMemory(pid, uImage, uImageSize);
	}

	KeUnstackDetachProcess(&kApcState);

	ExFreePool(kfileDll);

	return status;
}