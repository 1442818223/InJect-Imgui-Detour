#include <ntifs.h>
#include "Inject.h"
#include "dll.h"
EXTERN_C int _fltused = 1;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;// ������˳�����ӵ�����
	LIST_ENTRY InMemoryOrderLinks;// ���ڴ�˳�����ӵ�����
	LIST_ENTRY InInitializationOrderLinks;// ����ʼ��˳�����ӵ�����
	PVOID DllBase;// DLL �Ļ���ַ
	PVOID EntryPoint;// DLL ����ڵ��ַ  
	ULONG SizeOfImage;// DLL ӳ��Ĵ�С
	UNICODE_STRING FullDllName;// ������ DLL ����
	UNICODE_STRING BaseDllName;// DLL �Ļ�������
	ULONG Flags;// ��־
	USHORT LoadCount;// װ�ؼ�����
	USHORT TlsIndex;// TLS ����
	union {
		LIST_ENTRY HashLinks;// ��ϣ����
		struct {
			PVOID SectionPointer;// ��ָ��
			ULONG CheckSum;// У���
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;// ʱ���
		};
		struct {
			PVOID LoadedImports;// �Ѽ��صĵ����
		};
	};
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


ULONG64 LdrInPebOffset = 0x018;
ULONG64 ModListInPebOffset = 0x010;
EXTERN_C
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);//ֻ���õ��̵�,�����ò�ȫ
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
		return FALSE; // ����κ��ַ�������С����Сƥ�䳤�ȣ����� FALSE
	}

	for (SIZE_T i = 0; i <= sourceLength - minLength; i++) {
		SIZE_T matchCount = 0;

		// ��鵱ǰλ�õ��Ӵ��Ƿ�ƥ��
		for (SIZE_T j = 0; j < substringLength; j++) {
			if (Source[i + j] == Substring[j]) {
				matchCount++;
				if (matchCount >= minLength) {
					return TRUE; // �ҵ����� 5 ���ַ�ƥ��
				}
			}
			else {
				matchCount = 0; // ����ƥ�����
			}
		}
	}
	return FALSE; // δ�ҵ����� 5 ���ַ�ƥ��
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
				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+]�ҵ� DLL ��ַ=%p ��С=%ld ·��=%wZ\n", entry->DllBase,entry->SizeOfImage, &entry->FullDllName);
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
				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+]ƥ��Ľ��� PID = %lu\n", i);
				EnumModule(eproc, DllName, DllBase);
				ObDereferenceObject(eproc);
				return (HANDLE)i;  // ����ƥ���PID
			}
			ObDereferenceObject(eproc);
		}
	}
	return NULL;  // δ�ҵ�ƥ��Ľ���
}
HANDLE retPID(char* ProcessName) {
	ULONG i = 0;
	PEPROCESS eproc = NULL;

	for (i = 4; i < 100000000; i += 4) {
		eproc = LookupProcess((HANDLE)i);
		if (eproc != NULL) {
			// ��ȡ���̵�����·��
			//const char* imageName = (const char*)PsGetProcessImageFileName(eproc);

			// �����������Ƿ�ƥ������ 5 ���ַ�
			//if (StringContainsWithMinLength(imageName, ProcessName, 5))
			if (strstr((const char*)PsGetProcessImageFileName(eproc), ProcessName) != NULL)
			{
				// ��ӡƥ��Ľ��� PID
				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] ƥ��Ľ��� PID = %lu\n", i);
				ObDereferenceObject(eproc);
				return (HANDLE)i;  // ����ƥ���PID
			}

			// �ͷŽ��̶��������
			ObDereferenceObject(eproc);
		}
	}
	return NULL;  // δ�ҵ�ƥ��Ľ���
}
 //ͨ��ö�ٵķ�ʽ��λ��ָ���Ľ��̣��ҵ��ȴ�һ���ٻ�ȡģ���ַ
BOOLEAN WaitForProcess(CHAR* ProcessName) {
	BOOLEAN found = FALSE;
	ULONG i = 0;
	PEPROCESS eproc = NULL;

	for (i = 4; i < 100000000; i += 4) {
		// ���ҽ���
		eproc = LookupProcess((HANDLE)i);

		if (eproc != NULL) {
			// �� UCHAR* ǿ��ת��Ϊ const char*
			const char* imageName = (const char*)PsGetProcessImageFileName(eproc);

			// �����������Ƿ�ƥ������ 5 ���ַ�
			//if (StringContainsWithMinLength(imageName, ProcessName, 5)) 
				// �����������Ƿ�ƥ��
				if (strstr(imageName, ProcessName) != NULL)
			{
				// ��ӡƥ��Ľ��� PID
				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] ƥ��Ľ��� PID = %lu\n", i);
				found = TRUE;

				// �ͷŽ��̶�������
				ObDereferenceObject(eproc);
				break;  // �ҵ����̺��˳�ѭ��
			}

			// �ͷŽ��̶��������
			ObDereferenceObject(eproc);
		}
	}

	if (found) {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] �ҵ�����: %s\n", ProcessName);
	}
	else {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] δ�ҵ�����: %s\n", ProcessName);
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

		// ���û���ҵ����̣�����ѡ��ȴ�һ��ʱ�������
		LARGE_INTEGER shortInterval;
		shortInterval.QuadPart = -10000000LL;  // 1����ӳ٣���λΪ100����
		KeDelayExecutionThread(KernelMode, FALSE, &shortInterval);
	}

	//// �ڼ�⵽���̺�ȴ�15��
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] Waiting for 15 seconds...\n");
	LARGE_INTEGER interval;
	interval.QuadPart = -50000000LL;  // 10����ӳ٣���λΪ100����
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db+] Wait completed, continuing...\n");


	do {

		//pid = MyEnumModule("crossfire.exe", "crossfire.exe", &ModuleBase1);
		pid = retPID("crossfire.exe");
		//pid = retPID("MultiAnimation.exe");
		//LARGE_INTEGER interval;
		//interval.QuadPart = -30000000LL;  // 3����ӳ٣���λΪ100����  ���ȡ��̫��ȡ���������ַ
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