#include"dllmain.h"
#include <vector>


void 写字节集(ULONG64 address, std::vector<BYTE> 参_写入数据)
{
	if (IsBadReadPtr((VOID*)address, 1))
	{
		return;
	}

	//DWORD old_protect;
	//VirtualProtect((LPVOID)address, 参_写入数据.size(), 64, &old_protect);//修改内存属性
	for (size_t i = 0; i < 参_写入数据.size(); i++)
	{
		*(BYTE*)address++ = 参_写入数据[i];
	}
	//VirtualProtect((LPVOID)参_内存地址, 参_写入数据.size(), old_protect, &old_protect);//还原内存属性
}

extern ULONG64 MouDle1;
void  Show()
{
	

	写字节集((ULONG_PTR)(MouDle1 + 0x5E36F7), { 0 });


}

void  NoShow()
{
	

	写字节集((ULONG_PTR)(MouDle1 + 0x5E36F7), { 1 });


}