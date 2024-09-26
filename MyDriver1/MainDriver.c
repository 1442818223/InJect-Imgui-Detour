#include <ntifs.h>
#include "Inject.h"
#include "dll.h"
EXTERN_C int _fltused = 1;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;// 按加载顺序链接的链表
	LIST_ENTRY InMemoryOrderLinks;// 按内存顺序链接的链表
	LIST_ENTRY InInitializationOrderLinks;// 按初始化顺序链接的链表
	PVOID DllBase;// DLL 的基地址
	PVOID EntryPoint;// DLL 的入口点地址  
	ULONG SizeOfImage;// DLL 映像的大小
	UNICODE_STRING FullDllName;// 完整的 DLL 名称
	UNICODE_STRING BaseDllName;// DLL 的基本名称
	ULONG Flags;// 标志
	USHORT LoadCount;// 装载计数器
	USHORT TlsIndex;// TLS 索引
	union {
		LIST_ENTRY HashLinks;// 哈希链接
		struct {
			PVOID SectionPointer;// 段指针
			ULONG CheckSum;// 校验和
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;// 时间戳
		};
		struct {
			PVOID LoadedImports;// 已加载的导入表
		};
	};
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


ULONG64 LdrInPebOffset = 0x018;
ULONG64 ModListInPebOffset = 0x010;
EXTERN_C
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);//只能拿到短的,长的拿不全
EXTERN_C
NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);


ULONG_PTR ModuleBase1 = 0;
HANDLE pid = NULL;

BOOLEAN StringContainsWithMinLength(
	PCSTR Source,
	PCSTR Substring,
	SIZE_T minLength
) {
	SIZE_T sourceLength = strlen(Source);
	SIZE_T substringLength = strlen(Substring);

	if (substringLength < minLength || sourceLength < minLength) {
		return FALSE; // 如果任何字符串长度小于最小匹配长度，返回 FALSE
	}

	for (SIZE_T i = 0; i <= sourceLength - minLength; i++) {
		SIZE_T matchCount = 0;

		// 检查当前位置的子串是否匹配
		for (SIZE_T j = 0; j < substringLength; j++) {
			if (Source[i + j] == Substring[j]) {
				matchCount++;
				if (matchCount >= minLength) {
					return TRUE; // 找到至少 5 个字符匹配
				}
			}
			else {
				matchCount = 0; // 重置匹配计数
			}
		}
	}
	return FALSE; // 未找到至少 5 个字符匹配
}

VOID EnumModule(PEPROCESS Process, char* DllName, ULONG_PTR* DllBase)
{
	SIZE_T Peb = 0;
	SIZE_T Ldr = 0;
	PLIST_ENTRY ModListHead = 0;
	PLIST_ENTRY Module = 0;
	KAPC_STATE ks;
	UNICODE_STRING targetDllName;
	ANSI_STRING ansiString;

	if (!MmIsAddressValid(Process))
		return;

	Peb = (SIZE_T)PsGetProcessPeb(Process);

	if (!Peb)
		return;

	KeStackAttachProcess(Process, &ks);
	__try
	{
		Ldr = Peb + (SIZE_T)LdrInPebOffset;
		ProbeForRead((CONST PVOID)Ldr, 8, 8);
		ModListHead = (PLIST_ENTRY)(*(PULONG64)Ldr + ModListInPebOffset);
		ProbeForRead((CONST PVOID)ModListHead, 8, 8);
		Module = ModListHead->Flink;

		RtlInitAnsiString(&ansiString, DllName);
		RtlAnsiStringToUnicodeString(&targetDllName, &ansiString, TRUE);

		while (ModListHead != Module)
		{
			PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)Module;
			if (RtlCompareUnicodeString(&entry->BaseDllName, &targetDllName, TRUE) == 0)
			{
				*DllBase = (ULONG_PTR)entry->DllBase;
				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+]找到 DLL 基址=%p 大小=%ld 路径=%wZ\n", entry->DllBase,entry->SizeOfImage, &entry->FullDllName);
				break;
			}
			Module = Module->Flink;
			ProbeForRead((CONST PVOID)Module, 80, 8);
		}
		RtlFreeUnicodeString(&targetDllName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { ; }

	KeUnstackDetachProcess(&ks);
}


PEPROCESS LookupProcess(HANDLE Pid)
{
	PEPROCESS eprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &eprocess)))
		return eprocess;
	else
		return NULL;
}
HANDLE MyEnumModule(char* ProcessName, char* DllName, ULONG_PTR* DllBase)
{
	ULONG i = 0;
	PEPROCESS eproc = NULL;

	for (i = 4; i < 100000000; i = i + 4)
	{
		eproc = LookupProcess((HANDLE)i);
		if (eproc != NULL)
		{
			if (strstr((const char*)PsGetProcessImageFileName(eproc), ProcessName) != NULL)
			{
				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+]匹配的进程 PID = %lu\n", i);
				EnumModule(eproc, DllName, DllBase);
				ObDereferenceObject(eproc);
				return (HANDLE)i;  // 返回匹配的PID
			}
			ObDereferenceObject(eproc);
		}
	}
	return NULL;  // 未找到匹配的进程
}
HANDLE retPID(char* ProcessName) {
	ULONG i = 0;
	PEPROCESS eproc = NULL;

	for (i = 4; i < 100000000; i += 4) {
		eproc = LookupProcess((HANDLE)i);
		if (eproc != NULL) {
			// 获取进程的完整路径
			//const char* imageName = (const char*)PsGetProcessImageFileName(eproc);

			// 检查进程名称是否匹配至少 5 个字符
			//if (StringContainsWithMinLength(imageName, ProcessName, 5))
			if (strstr((const char*)PsGetProcessImageFileName(eproc), ProcessName) != NULL)
			{
				// 打印匹配的进程 PID
				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] 匹配的进程 PID = %lu\n", i);
				ObDereferenceObject(eproc);
				return (HANDLE)i;  // 返回匹配的PID
			}

			// 释放进程对象的引用
			ObDereferenceObject(eproc);
		}
	}
	return NULL;  // 未找到匹配的进程
}
 //通过枚举的方式定位到指定的进程，找到等待一会再获取模块基址
BOOLEAN WaitForProcess(CHAR* ProcessName) {
	BOOLEAN found = FALSE;
	ULONG i = 0;
	PEPROCESS eproc = NULL;

	for (i = 4; i < 100000000; i += 4) {
		// 查找进程
		eproc = LookupProcess((HANDLE)i);

		if (eproc != NULL) {
			// 将 UCHAR* 强制转换为 const char*
			const char* imageName = (const char*)PsGetProcessImageFileName(eproc);

			// 检查进程名称是否匹配至少 5 个字符
			//if (StringContainsWithMinLength(imageName, ProcessName, 5)) 
				// 检查进程名称是否匹配
				if (strstr(imageName, ProcessName) != NULL)
			{
				// 打印匹配的进程 PID
				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] 匹配的进程 PID = %lu\n", i);
				found = TRUE;

				// 释放进程对象引用
				ObDereferenceObject(eproc);
				break;  // 找到进程后退出循环
			}

			// 释放进程对象的引用
			ObDereferenceObject(eproc);
		}
	}

	if (found) {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] 找到进程: %s\n", ProcessName);
	}
	else {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] 未找到进程: %s\n", ProcessName);
	}

	return found;
}


VOID DriverUnload(PDRIVER_OBJECT pDriver)
{

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{

	while (1)
	{
		if (WaitForProcess("crossfire.exe"))
			//if (WaitForProcess("MultiAnimation.exe"))
		{
				
			break;
		}

		// 如果没有找到进程，可以选择等待一段时间后重试
		LARGE_INTEGER shortInterval;
		shortInterval.QuadPart = -10000000LL;  // 1秒的延迟，单位为100纳秒
		KeDelayExecutionThread(KernelMode, FALSE, &shortInterval);
	}

	//// 在检测到进程后等待15秒
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] Waiting for 15 seconds...\n");
	LARGE_INTEGER interval;
	interval.QuadPart = -50000000LL;  // 10秒的延迟，单位为100纳秒
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] Wait completed, continuing...\n");


	do {

		//pid = MyEnumModule("crossfire.exe", "crossfire.exe", &ModuleBase1);
		pid = retPID("crossfire.exe");
		//pid = retPID("MultiAnimation.exe");
		//LARGE_INTEGER interval;
		//interval.QuadPart = -30000000LL;  // 3秒的延迟，单位为100纳秒  免得取得太急取不到下面基址
		//KeDelayExecutionThread(KernelMode, FALSE, &interval);
		//pid = MyEnumModule("crossfire.exe", "cshell_x64.dll", &ModuleBase2);

		//pid = MyEnumModule("Bandizip.exe", "ark.x64.dll", &ModuleBase1);

	} while (pid == NULL);

	interval.QuadPart = -70000000LL;
	KeDelayExecutionThread(KernelMode, FALSE, &interval);

	SIZE_T dwImageSize = sizeof(sysData);
	unsigned char * pMemory = (unsigned char *)ExAllocatePool(PagedPool,dwImageSize);
	memcpy(pMemory, sysData, dwImageSize);
	for (ULONG i = 0; i < dwImageSize; i++)
	{
		pMemory[i] ^= 0xd8;
		pMemory[i] ^= 0xcd;
	}
	
	InjectX64(pid, pMemory, dwImageSize);
	ExFreePool(pMemory);
	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}