#include"dllmain.h"
#include <vector>


void д�ֽڼ�(ULONG64 address, std::vector<BYTE> ��_д������)
{
	if (IsBadReadPtr((VOID*)address, 1))
	{
		return;
	}

	//DWORD old_protect;
	//VirtualProtect((LPVOID)address, ��_д������.size(), 64, &old_protect);//�޸��ڴ�����
	for (size_t i = 0; i < ��_д������.size(); i++)
	{
		*(BYTE*)address++ = ��_д������[i];
	}
	//VirtualProtect((LPVOID)��_�ڴ��ַ, ��_д������.size(), old_protect, &old_protect);//��ԭ�ڴ�����
}

extern ULONG64 MouDle1;
void  Show()
{
	

	д�ֽڼ�((ULONG_PTR)(MouDle1 + 0x5E36F7), { 0 });


}

void  NoShow()
{
	

	д�ֽڼ�((ULONG_PTR)(MouDle1 + 0x5E36F7), { 1 });


}