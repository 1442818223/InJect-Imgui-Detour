#include "dllmain.h"

//��ʼhook
void Helpers::HookFunction(PVOID* oFunction, PVOID Function)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(oFunction, Function);
	DetourTransactionCommit();

}

//����hook
void Helpers::UnHookFunction(PVOID* oFunction, PVOID Function)
{

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(oFunction, Function);
	DetourTransactionCommit();


}

